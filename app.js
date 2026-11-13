/* HomeVault — app.js
 * Finanças da casa com criptografia no aparelho (AES-GCM 256, chave derivada da
 * senha da casa via PBKDF2-SHA256). O banco (Firebase Realtime Database) só
 * recebe texto cifrado; as regras do banco ainda restringem cada casa a seus membros.
 */
(function () {
'use strict';

var VERSAO = '1.0.0';
var PBKDF2_ITER = 310000;
var VERIF_TEXTO = 'HOMEVAULT-OK';

// ───────────────────────── utilitários ─────────────────────────
function $(id) { return document.getElementById(id); }
function qsa(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
var _toastT;
function toast(msg) {
  var t = $('toast'); t.textContent = msg; t.classList.add('on');
  clearTimeout(_toastT); _toastT = setTimeout(function () { t.classList.remove('on'); }, 2200);
}
var ALFA = 'abcdefghijkmnpqrstuvwxyz23456789';
function rid(n) {
  var b = new Uint8Array(n), s = '';
  crypto.getRandomValues(b);
  for (var i = 0; i < n; i++) s += ALFA[b[i] % ALFA.length];
  return s;
}
function hojeISO() {
  var d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
function mesDe(iso) { return iso.slice(0, 7); }
function somaMes(ym, n) {
  var y = +ym.slice(0, 4), m = +ym.slice(5, 7) - 1 + n;
  y += Math.floor(m / 12); m = ((m % 12) + 12) % 12;
  return y + '-' + String(m + 1).padStart(2, '0');
}
function nomeMes(ym, curto) {
  var d = new Date(+ym.slice(0, 4), +ym.slice(5, 7) - 1, 1);
  return maiuscula(d.toLocaleDateString('pt-BR', curto ? { month: 'short' } : { month: 'long', year: 'numeric' }).replace('.', ''));
}
function maiuscula(t) { return t.charAt(0).toUpperCase() + t.slice(1); }
function nomeDia(iso) {
  var d = new Date(+iso.slice(0, 4), +iso.slice(5, 7) - 1, +iso.slice(8, 10));
  return maiuscula(d.toLocaleDateString('pt-BR', { weekday: 'long', day: 'numeric', month: 'long' }));
}
var _fmt = null, _fmtMoeda = null;
function dinheiro(cent) {
  var moeda = (S.cfg && S.cfg.moeda) || 'CAD';
  if (!_fmt || _fmtMoeda !== moeda) {
    _fmt = new Intl.NumberFormat('pt-BR', { style: 'currency', currency: moeda });
    _fmtMoeda = moeda;
  }
  return _fmt.format((cent || 0) / 100);
}
// Aceita "12,50", "12.50", "1.234,56", "1,234.56"
function lerValor(txt) {
  var s = String(txt || '').replace(/[^\d.,]/g, '');
  if (!s) return NaN;
  var ultV = s.lastIndexOf(','), ultP = s.lastIndexOf('.');
  var dec = Math.max(ultV, ultP);
  if (dec >= 0 && s.length - dec - 1 <= 2) {
    s = s.slice(0, dec).replace(/[.,]/g, '') + '.' + s.slice(dec + 1);
  } else {
    s = s.replace(/[.,]/g, '');
  }
  var n = parseFloat(s);
  return isFinite(n) ? Math.round(n * 100) : NaN;
}
function centParaTexto(c) { return (c / 100).toFixed(2).replace('.', ','); }

// ───────────────────────── criptografia ─────────────────────────
var enc = new TextEncoder(), dec = new TextDecoder();
function b64(buf) {
  var bytes = new Uint8Array(buf), s = '';
  for (var i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(str) {
  var s = atob(str), b = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b;
}
function derivarChave(senha, saltB64) {
  return crypto.subtle.importKey('raw', enc.encode(senha), 'PBKDF2', false, ['deriveKey']).then(function (base) {
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: unb64(saltB64), iterations: PBKDF2_ITER, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  });
}
function cifrar(chave, obj) {
  var iv = crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, chave, enc.encode(JSON.stringify(obj)))
    .then(function (ct) { return { iv: b64(iv), d: b64(ct) }; });
}
function decifrar(chave, pac) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(pac.iv) }, chave, unb64(pac.d))
    .then(function (pt) { return JSON.parse(dec.decode(pt)); });
}

// Guarda a chave (não-exportável) no IndexedDB deste aparelho
var IDB = {
  abrir: function () {
    return new Promise(function (ok, erro) {
      var r = indexedDB.open('homevault', 1);
      r.onupgradeneeded = function () { r.result.createObjectStore('chaves'); };
      r.onsuccess = function () { ok(r.result); };
      r.onerror = function () { erro(r.error); };
    });
  },
  op: function (modo, fn) {
    return IDB.abrir().then(function (db) {
      return new Promise(function (ok, erro) {
        var tx = db.transaction('chaves', modo), st = tx.objectStore('chaves');
        var req = fn(st);
        tx.oncomplete = function () { ok(req && req.result); };
        tx.onerror = function () { erro(tx.error); };
      });
    });
  },
  get: function (k) { return IDB.op('readonly', function (s) { return s.get(k); }).catch(function () { return null; }); },
  set: function (k, v) { return IDB.op('readwrite', function (s) { return s.put(v, k); }).catch(function () {}); },
  del: function (k) { return IDB.op('readwrite', function (s) { return s.delete(k); }).catch(function () {}); }
};

// ───────────────────────── estado ─────────────────────────
var S = {
  user: null, casa: null, chave: null, meta: null,
  cfg: null, lanc: {}, perfis: {}, membros: {},
  mes: mesDe(hojeISO()), tela: 'lancar',
  lc: { tipo: 'despesa', cat: null, sub: null, editando: null },
  ajTipo: 'despesa', refs: []
};
var db, auth;

// ───────────────────────── telas ─────────────────────────
var TELAS_APP = ['lancar', 'hist', 'resumo', 'ajustes'];
function mostrar(nome) {
  qsa('.scr').forEach(function (s) { s.classList.remove('ativa'); });
  $('scr-' + nome).classList.add('ativa');
  var app = TELAS_APP.indexOf(nome) >= 0;
  $('nav').classList.toggle('on', app);
  document.body.classList.toggle('sem-nav', !app);
  if (app) {
    S.tela = nome;
    qsa('#nav button').forEach(function (b) { b.classList.toggle('on', b.dataset.ir === nome); });
    render();
  }
  window.scrollTo(0, 0);
}

// ───────────────────────── categorias padrão ─────────────────────────
function catsPadrao() {
  function c(tipo, emoji, nome, subs) {
    return { id: rid(8), tipo: tipo, emoji: emoji, nome: nome, subs: subs.map(function (n) { return { id: rid(8), nome: n }; }) };
  }
  return [
    c('despesa', '🏠', 'Moradia', ['Aluguel / Financiamento', 'Luz', 'Água', 'Internet / Telefone', 'Manutenção']),
    c('despesa', '🛒', 'Mercado', ['Supermercado', 'Feira', 'Padaria']),
    c('despesa', '🚗', 'Transporte', ['Combustível', 'Manutenção', 'Seguro', 'Estacionamento', 'Transporte público']),
    c('despesa', '🩺', 'Saúde', ['Farmácia', 'Consultas', 'Plano de saúde']),
    c('despesa', '🍽️', 'Restaurantes', ['Restaurante', 'Delivery', 'Café']),
    c('despesa', '🎉', 'Lazer', ['Passeios', 'Assinaturas', 'Viagens']),
    c('despesa', '📚', 'Educação', ['Escola', 'Cursos', 'Livros']),
    c('despesa', '🐾', 'Pets', ['Ração', 'Veterinário']),
    c('despesa', '👕', 'Compras', ['Roupas', 'Casa', 'Eletrônicos']),
    c('despesa', '💳', 'Contas e taxas', ['Cartão', 'Banco', 'Impostos']),
    c('despesa', '📦', 'Outros', []),
    c('receita', '💼', 'Salário', []),
    c('receita', '💰', 'Renda extra', []),
    c('receita', '📈', 'Investimentos', []),
    c('receita', '🎁', 'Outras receitas', [])
  ];
}
function catPorId(id) {
  var cs = (S.cfg && S.cfg.cats) || [];
  for (var i = 0; i < cs.length; i++) if (cs[i].id === id) return cs[i];
  return null;
}
function subPorId(cat, id) {
  if (!cat || !id) return null;
  for (var i = 0; i < cat.subs.length; i++) if (cat.subs[i].id === id) return cat.subs[i];
  return null;
}

// ───────────────────────── início ─────────────────────────
function iniciar() {
  var cfg = window.HOMEVAULT_FIREBASE;
  if (!cfg || !cfg.apiKey || /COLE_AQUI/.test(cfg.apiKey) || typeof firebase === 'undefined') {
    mostrar('semconfig'); return;
  }
  firebase.initializeApp(cfg);
  auth = firebase.auth(); db = firebase.database();
  ligarEventos();
  auth.onAuthStateChanged(function (u) {
    pararEscuta();
    limparFormularios();
    S.user = u; S.casa = null; S.chave = null; S.cfg = null; S.lanc = {}; S.perfis = {}; S.membros = {};
    if (!u) { mostrar('auth'); return; }
    carregarCasa();
  });
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(function () {});
  $('aj-versao').textContent = VERSAO;
}

// Ao trocar de usuário, nada digitado pela pessoa anterior pode ficar na tela
function limparFormularios() {
  qsa('#scr-auth input, #scr-casa input, #scr-unlock input').forEach(function (i) {
    if (i.type === 'checkbox') i.checked = i.id === 'ul-lembrar'; else i.value = '';
  });
  qsa('.erro').forEach(function (e) { e.textContent = ''; });
  $('tab-nova').click();
  setModoCriar(false);
  $('nc-moeda').value = 'CAD';
  $('hi-busca').value = ''; $('hi-cat').value = '';
  fecharModal();
}

function carregarCasa() {
  mostrar('load');
  db.ref('usuarios/' + S.user.uid + '/casa').once('value').then(function (snap) {
    var casa = snap.val();
    if (!casa) { mostrar('casa'); return; }
    return db.ref('casas/' + casa).once('value').then(function (cs) {
      var m = cs.val();
      if (!m || !m.salt) throw { code: 'PERMISSION_DENIED' };
      S.casa = casa; S.meta = m;
      return IDB.get(S.user.uid + ':' + casa).then(function (k) {
        if (!k) { mostrar('unlock'); return; }
        return decifrar(k, m.verif).then(function () { abrirCasa(k); }, function () { mostrar('unlock'); });
      });
    });
  }).catch(function (e) {
    if (e && /PERMISSION_DENIED|permission/i.test(e.code || e.message || '')) {
      // Foi removido da casa (ou ela não existe mais)
      db.ref('usuarios/' + S.user.uid + '/casa').remove().catch(function () {});
      mostrar('casa');
      $('nc-erro').textContent = 'Você não tem mais acesso à casa anterior. Crie uma casa ou use um convite.';
    } else {
      mostrar('load');
      document.querySelector('#scr-load .carregando').innerHTML =
        'Não foi possível conectar.<br><button class="link" onclick="location.reload()">Tentar de novo</button>';
    }
  });
}

function abrirCasa(chave) {
  S.chave = chave;
  escutar();
  mostrar('lancar');
  resetForm();
}

// ───────────────────────── escuta em tempo real ─────────────────────────
function pararEscuta() {
  S.refs.forEach(function (r) { r.off(); });
  S.refs = [];
}
var _renderT;
function renderLogo() { clearTimeout(_renderT); _renderT = setTimeout(render, 60); }

function escutar() {
  pararEscuta();
  var base = 'casas/' + S.casa;
  var rCfg = db.ref(base + '/dados/config');
  var rLanc = db.ref(base + '/dados/lanc');
  var rPerf = db.ref(base + '/dados/perfis');
  var rMem = db.ref(base + '/membros');
  var rConv = db.ref(base + '/convite');
  var rCon = db.ref('.info/connected');
  S.refs = [rCfg, rLanc, rPerf, rMem, rConv, rCon];

  var negado = function () { carregarCasa(); };

  rCfg.on('value', function (s) {
    if (!s.val()) return;
    decifrar(S.chave, s.val()).then(function (c) { S.cfg = c; renderLogo(); });
  }, negado);

  function addLanc(s) {
    var id = s.key;
    decifrar(S.chave, s.val()).then(function (l) { l.id = id; S.lanc[id] = l; renderLogo(); }, function () {});
  }
  rLanc.on('child_added', addLanc, negado);
  rLanc.on('child_changed', addLanc);
  rLanc.on('child_removed', function (s) { delete S.lanc[s.key]; renderLogo(); });

  rPerf.on('value', function (s) {
    var v = s.val() || {}, ids = Object.keys(v), out = {};
    Promise.all(ids.map(function (uid) {
      return decifrar(S.chave, v[uid]).then(function (p) { out[uid] = p; }, function () {});
    })).then(function () { S.perfis = out; renderLogo(); });
  });
  rMem.on('value', function (s) { S.membros = s.val() || {}; renderLogo(); });
  rConv.on('value', function (s) { S.meta.convite = s.val(); renderLogo(); });
  rCon.on('value', function (s) {
    var on = !!s.val(), el = $('sync');
    el.className = on ? 'on' : 'off';
    el.querySelector('span').textContent = on ? 'sincronizado' : 'offline';
  });
}

// ───────────────────────── login / cadastro ─────────────────────────
var modoCriar = false;
function msgAuth(e) {
  var c = (e && e.code) || '';
  if (/invalid-credential|wrong-password|user-not-found|invalid-login/.test(c)) return 'E-mail ou senha incorretos.';
  if (/email-already-in-use/.test(c)) return 'Já existe uma conta com este e-mail. Use "Entrar".';
  if (/weak-password/.test(c)) return 'Senha fraca. Use pelo menos 8 caracteres.';
  if (/invalid-email/.test(c)) return 'E-mail inválido.';
  if (/too-many-requests/.test(c)) return 'Muitas tentativas. Aguarde alguns minutos.';
  if (/network/.test(c)) return 'Sem conexão com a internet.';
  if (/operation-not-allowed/.test(c)) return 'Login por e-mail não está ativado no Firebase.';
  return 'Não foi possível concluir (' + (c || 'erro') + ').';
}
function setModoCriar(v) {
  modoCriar = v;
  $('tab-entrar').classList.toggle('on', !v); $('tab-criar').classList.toggle('on', v);
  $('campo-nome').style.display = v ? '' : 'none';
  $('au-btn').textContent = v ? 'Criar conta' : 'Entrar';
  $('au-esqueci').style.display = v ? 'none' : '';
  $('au-senha').setAttribute('autocomplete', v ? 'new-password' : 'current-password');
  $('au-erro').textContent = '';
}
function enviarAuth() {
  var email = $('au-email').value.trim(), senha = $('au-senha').value, nome = $('au-nome').value.trim();
  var er = $('au-erro'); er.textContent = '';
  if (!email || !senha) { er.textContent = 'Preencha e-mail e senha.'; return; }
  if (modoCriar && !nome) { er.textContent = 'Informe seu nome.'; return; }
  if (modoCriar && senha.length < 8) { er.textContent = 'A senha precisa ter pelo menos 8 caracteres.'; return; }
  var btn = $('au-btn'); btn.disabled = true;
  var p = modoCriar
    ? auth.createUserWithEmailAndPassword(email, senha).then(function (r) { return r.user.updateProfile({ displayName: nome }); })
    : auth.signInWithEmailAndPassword(email, senha);
  p.catch(function (e) { er.textContent = msgAuth(e); }).then(function () { btn.disabled = false; });
}
function esqueci() {
  var email = $('au-email').value.trim();
  if (!email) { $('au-erro').textContent = 'Digite seu e-mail acima e toque de novo em "Esqueci minha senha".'; return; }
  auth.sendPasswordResetEmail(email).then(function () {
    $('au-erro').innerHTML = '<span class="ok">Enviamos um e-mail para redefinir a senha.</span>';
  }, function (e) { $('au-erro').textContent = msgAuth(e); });
}
function nomeUsuario() {
  return (S.user && (S.user.displayName || (S.user.email || '').split('@')[0])) || 'Eu';
}

// ───────────────────────── criar / entrar em casa ─────────────────────────
function criarCasa() {
  var nome = $('nc-nome').value.trim(), moeda = $('nc-moeda').value;
  var s1 = $('nc-senha').value, s2 = $('nc-senha2').value, er = $('nc-erro');
  er.textContent = '';
  if (!nome) { er.textContent = 'Dê um nome para a casa.'; return; }
  if (s1.length < 8) { er.textContent = 'A senha da casa precisa ter pelo menos 8 caracteres.'; return; }
  if (s1 !== s2) { er.textContent = 'As senhas da casa não conferem.'; return; }
  if (!$('nc-ciente').checked) { er.textContent = 'Confirme que anotou a senha da casa.'; return; }
  var btn = $('nc-btn'); btn.disabled = true; btn.textContent = 'Criando…';
  var casa = rid(20), convite = rid(24);
  var salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  var chave;
  derivarChave(s1, salt).then(function (k) {
    chave = k;
    return cifrar(k, VERIF_TEXTO);
  }).then(function (verif) {
    var m = {}; m[S.user.uid] = convite;
    return db.ref('casas/' + casa).set({
      dono: S.user.uid, convite: convite, salt: salt, verif: verif, membros: m,
      criada: firebase.database.ServerValue.TIMESTAMP
    });
  }).then(function () {
    return cifrar(chave, { nome: nome, moeda: moeda, cats: catsPadrao() });
  }).then(function (c) {
    return db.ref('casas/' + casa + '/dados/config').set(c);
  }).then(function () {
    return entrouNaCasa(casa, chave, true);
  }).catch(function (e) {
    er.textContent = 'Não foi possível criar a casa (' + ((e && e.code) || e) + ').';
  }).then(function () { btn.disabled = false; btn.textContent = 'Criar casa'; });
}

function lerConvite(txt) {
  var m = String(txt || '').trim().toLowerCase().replace(/\s+/g, '').match(/^hv-([a-z0-9]{20})-([a-z0-9]{24})$/);
  return m ? { casa: m[1], convite: m[2] } : null;
}
function entrarConvite() {
  var cv = lerConvite($('cv-codigo').value), senha = $('cv-senha').value, er = $('cv-erro');
  er.textContent = '';
  if (!cv) { er.textContent = 'Código de convite inválido. Confira se copiou inteiro (começa com HV-).'; return; }
  if (!senha) { er.textContent = 'Digite a senha da casa.'; return; }
  var btn = $('cv-btn'); btn.disabled = true; btn.textContent = 'Entrando…';
  var memRef = db.ref('casas/' + cv.casa + '/membros/' + S.user.uid);
  memRef.set(cv.convite).then(function () {
    return db.ref('casas/' + cv.casa).once('value');
  }, function () {
    throw { msg: 'Convite inválido ou expirado. Peça um código novo.' };
  }).then(function (snap) {
    var m = snap.val();
    return derivarChave(senha, m.salt).then(function (k) {
      return decifrar(k, m.verif).then(function () {
        S.meta = m;
        return entrouNaCasa(cv.casa, k, false);
      }, function () {
        return memRef.remove().then(function () { throw { msg: 'Senha da casa incorreta.' }; });
      });
    });
  }).catch(function (e) {
    er.textContent = (e && e.msg) || 'Não foi possível entrar (' + ((e && e.code) || e) + ').';
  }).then(function () { btn.disabled = false; btn.textContent = 'Entrar na casa'; });
}

function entrouNaCasa(casa, chave, criou) {
  return db.ref('usuarios/' + S.user.uid + '/casa').set(casa).then(function () {
    return IDB.set(S.user.uid + ':' + casa, chave);
  }).then(function () {
    return cifrar(chave, { nome: nomeUsuario(), email: S.user.email || '' });
  }).then(function (p) {
    return db.ref('casas/' + casa + '/dados/perfis/' + S.user.uid).set(p);
  }).then(function () {
    return db.ref('casas/' + casa).once('value');
  }).then(function (snap) {
    S.casa = casa; S.meta = snap.val();
    abrirCasa(chave);
    toast(criou ? 'Casa criada! 🎉' : 'Bem-vindo(a) à casa!');
  });
}

function desbloquear() {
  var senha = $('ul-senha').value, er = $('ul-erro');
  er.textContent = '';
  if (!senha) { er.textContent = 'Digite a senha da casa.'; return; }
  var btn = $('ul-btn'); btn.disabled = true; btn.textContent = 'Verificando…';
  derivarChave(senha, S.meta.salt).then(function (k) {
    return decifrar(k, S.meta.verif).then(function () {
      var p = $('ul-lembrar').checked ? IDB.set(S.user.uid + ':' + S.casa, k) : Promise.resolve();
      return p.then(function () { $('ul-senha').value = ''; abrirCasa(k); });
    }, function () { er.textContent = 'Senha da casa incorreta.'; });
  }).catch(function () { er.textContent = 'Não foi possível desbloquear.'; })
    .then(function () { btn.disabled = false; btn.textContent = 'Desbloquear'; });
}

function bloquear() {
  IDB.del(S.user.uid + ':' + S.casa).then(function () {
    pararEscuta(); S.chave = null; S.lanc = {}; S.cfg = null;
    mostrar('unlock');
  });
}

function sair() {
  var p = (S.user && S.casa) ? IDB.del(S.user.uid + ':' + S.casa) : Promise.resolve();
  p.then(function () { pararEscuta(); return auth.signOut(); });
}

// ───────────────────────── salvar dados ─────────────────────────
function salvarCfg() {
  return cifrar(S.chave, S.cfg).then(function (c) {
    return db.ref('casas/' + S.casa + '/dados/config').set(c);
  });
}
function salvarLanc(l) {
  var id = l.id || (Date.now().toString(36) + rid(6));
  var dado = { v: l.v, t: l.t, dt: l.dt, c: l.c || null, s: l.s || null, d: l.d || '', por: l.por || S.user.uid, ts: l.ts || Date.now() };
  S.lanc[id] = Object.assign({ id: id }, dado); // mostra na hora
  renderLogo();
  return cifrar(S.chave, dado).then(function (c) {
    return db.ref('casas/' + S.casa + '/dados/lanc/' + id).set(c);
  });
}
function excluirLanc(id) {
  delete S.lanc[id]; renderLogo();
  return db.ref('casas/' + S.casa + '/dados/lanc/' + id).remove();
}

// ───────────────────────── render ─────────────────────────
function render() {
  if (!S.chave) return;
  if (S.tela === 'lancar') renderLancar();
  else if (S.tela === 'hist') renderHist();
  else if (S.tela === 'resumo') renderResumo();
  else if (S.tela === 'ajustes') renderAjustes();
}

// Lançar
function resetForm() {
  S.lc = { tipo: 'despesa', cat: null, sub: null, editando: null };
  $('lc-valor').value = ''; $('lc-desc').value = ''; $('lc-data').value = hojeISO();
  $('lc-erro').textContent = '';
  $('lc-titulo').textContent = 'Novo lançamento';
  $('lc-btn').textContent = 'Salvar';
  $('lc-edbtns').style.display = 'none';
  render();
}
function renderLancar() {
  qsa('[data-tipo]').forEach(function (b) { b.classList.toggle('on', b.dataset.tipo === S.lc.tipo); });
  var cats = ((S.cfg && S.cfg.cats) || []).filter(function (c) { return c.tipo === S.lc.tipo; });
  if (!S.cfg) { $('lc-cats').innerHTML = '<span class="muted small">Carregando categorias…</span>'; return; }
  if (!cats.length) { $('lc-cats').innerHTML = '<span class="muted small">Nenhuma categoria. Crie em Ajustes.</span>'; }
  else $('lc-cats').innerHTML = cats.map(function (c) {
    return '<button class="chip' + (c.id === S.lc.cat ? ' on' : '') + '" data-cat="' + c.id + '">' + esc(c.emoji) + ' ' + esc(c.nome) + '</button>';
  }).join('');
  var cat = catPorId(S.lc.cat);
  if (cat && cat.subs.length) {
    $('lc-subbox').style.display = '';
    $('lc-subs').innerHTML = cat.subs.map(function (s) {
      return '<button class="chip' + (s.id === S.lc.sub ? ' on' : '') + '" data-sub="' + s.id + '">' + esc(s.nome) + '</button>';
    }).join('');
  } else $('lc-subbox').style.display = 'none';
}
function salvarForm() {
  var er = $('lc-erro'); er.textContent = '';
  var v = lerValor($('lc-valor').value);
  if (!(v > 0)) { er.textContent = 'Informe um valor.'; $('lc-valor').focus(); return; }
  if (!S.lc.cat) { er.textContent = 'Escolha uma categoria.'; return; }
  var dt = $('lc-data').value || hojeISO();
  var ant = S.lc.editando ? S.lanc[S.lc.editando] : null;
  var l = { id: S.lc.editando, v: v, t: S.lc.tipo, dt: dt, c: S.lc.cat, s: S.lc.sub, d: $('lc-desc').value.trim(),
    por: ant ? ant.por : S.user.uid, ts: ant ? ant.ts : Date.now() };
  var editando = !!S.lc.editando;
  salvarLanc(l).catch(function () { toast('⚠️ Erro ao salvar. Verifique a conexão.'); });
  toast(editando ? 'Lançamento atualizado' : 'Lançamento salvo ✓');
  if (editando) { S.mes = mesDe(dt); resetForm(); mostrar('hist'); }
  else {
    var tipo = S.lc.tipo; resetForm(); S.lc.tipo = tipo; renderLancar();
  }
}
function editar(id) {
  var l = S.lanc[id]; if (!l) return;
  S.lc = { tipo: l.t, cat: l.c, sub: l.s, editando: id };
  $('lc-valor').value = centParaTexto(l.v);
  $('lc-data').value = l.dt; $('lc-desc').value = l.d || '';
  $('lc-titulo').textContent = 'Editar lançamento';
  $('lc-btn').textContent = 'Salvar alterações';
  $('lc-edbtns').style.display = 'flex';
  $('lc-erro').textContent = '';
  mostrar('lancar');
}

// Histórico
function lancDoMes(ym) {
  return Object.keys(S.lanc).map(function (k) { return S.lanc[k]; })
    .filter(function (l) { return l.dt && l.dt.slice(0, 7) === ym; });
}
function renderHist() {
  $('hi-mes').textContent = nomeMes(S.mes);
  var sel = $('hi-cat'), atual = sel.value;
  var cats = (S.cfg && S.cfg.cats) || [];
  sel.innerHTML = '<option value="">Todas</option>' + cats.map(function (c) {
    return '<option value="' + c.id + '">' + esc(c.emoji + ' ' + c.nome) + '</option>';
  }).join('');
  sel.value = atual;
  var busca = $('hi-busca').value.trim().toLowerCase();
  var lista = lancDoMes(S.mes).filter(function (l) {
    if (sel.value && l.c !== sel.value) return false;
    if (!busca) return true;
    var c = catPorId(l.c), s = subPorId(c, l.s);
    return ((l.d || '') + ' ' + (c ? c.nome : '') + ' ' + (s ? s.nome : '')).toLowerCase().indexOf(busca) >= 0;
  }).sort(function (a, b) { return a.dt < b.dt ? 1 : a.dt > b.dt ? -1 : (b.ts || 0) - (a.ts || 0); });
  if (!lista.length) { $('hi-lista').innerHTML = '<div class="vazio">Nenhum lançamento neste mês.</div>'; return; }
  var html = '', dia = '', multi = Object.keys(S.membros).length > 1;
  lista.forEach(function (l) {
    if (l.dt !== dia) { dia = l.dt; html += '<div class="dia">' + esc(nomeDia(dia)) + '</div>'; }
    var c = catPorId(l.c), s = subPorId(c, l.s);
    var quem = multi && S.perfis[l.por] ? ' · ' + esc(S.perfis[l.por].nome) : '';
    var nomeCat = c ? c.nome : 'Sem categoria';
    var titulo = l.d || (s ? s.nome : nomeCat);
    var sub = esc(nomeCat) + (s ? ' › ' + esc(s.nome) : '');
    if (!l.d && !s) sub = l.t === 'receita' ? 'Receita' : 'Despesa';
    html += '<div class="item" data-ed="' + l.id + '"><div class="em">' + esc(c ? c.emoji : '❔') + '</div>' +
      '<div class="tx"><b>' + esc(titulo) + '</b><span>' + sub + quem + '</span></div>' +
      '<div class="v ' + (l.t === 'receita' ? 'rec' : 'desp') + '">' + (l.t === 'receita' ? '+' : '−') + esc(dinheiro(l.v)) + '</div></div>';
  });
  $('hi-lista').innerHTML = html;
}

// Resumo
function renderResumo() {
  $('rs-mes').textContent = nomeMes(S.mes);
  var lista = lancDoMes(S.mes), rec = 0, desp = 0, porCat = {};
  lista.forEach(function (l) {
    if (l.t === 'receita') rec += l.v;
    else {
      desp += l.v;
      var k = l.c || '_';
      porCat[k] = porCat[k] || { tot: 0, subs: {} };
      porCat[k].tot += l.v;
      var sk = l.s || '_';
      porCat[k].subs[sk] = (porCat[k].subs[sk] || 0) + l.v;
    }
  });
  $('rs-rec').textContent = dinheiro(rec);
  $('rs-desp').textContent = dinheiro(desp);
  var sal = $('rs-saldo'); sal.textContent = dinheiro(rec - desp);
  sal.style.color = rec - desp >= 0 ? 'var(--ok)' : 'var(--bad)';
  var ks = Object.keys(porCat).sort(function (a, b) { return porCat[b].tot - porCat[a].tot; });
  if (!ks.length) $('rs-cats').innerHTML = '<div class="vazio">Sem despesas neste mês.</div>';
  else $('rs-cats').innerHTML = ks.map(function (k) {
    var c = catPorId(k), p = porCat[k], pct = desp ? Math.round(p.tot * 100 / desp) : 0;
    var subs = Object.keys(p.subs).sort(function (a, b) { return p.subs[b] - p.subs[a]; }).map(function (sk) {
      var s = subPorId(c, sk);
      return '<div><span>' + esc(s ? s.nome : 'Sem subcategoria') + '</span><span>' + esc(dinheiro(p.subs[sk])) + '</span></div>';
    }).join('');
    return '<div class="catlin"><div class="row"><span>' + esc(c ? c.emoji + ' ' + c.nome : '❔ Sem categoria') +
      '</span><span><b>' + esc(dinheiro(p.tot)) + '</b> <span class="muted small">' + pct + '%</span></span></div>' +
      '<div class="bar"><i style="width:' + pct + '%"></i></div><div class="subs">' + subs + '</div></div>';
  }).join('');
  // últimos 6 meses
  var meses = [], max = 0;
  for (var i = 5; i >= 0; i--) {
    var ym = somaMes(S.mes, -i), t = 0;
    lancDoMes(ym).forEach(function (l) { if (l.t !== 'receita') t += l.v; });
    meses.push({ ym: ym, t: t }); if (t > max) max = t;
  }
  $('rs-meses').innerHTML = meses.map(function (m) {
    var h = max ? Math.max(2, Math.round(m.t * 100 / max)) : 2;
    return '<div class="' + (m.ym === S.mes ? 'atual' : '') + '" title="' + esc(dinheiro(m.t)) + '"><i style="height:' + h + '%"></i>' + esc(nomeMes(m.ym, true)) + '</div>';
  }).join('');
}

// Ajustes
function codigoConvite() { return S.meta && S.meta.convite ? 'HV-' + S.casa + '-' + S.meta.convite : ''; }
function souDono() { return S.meta && S.user && S.meta.dono === S.user.uid; }
function renderAjustes() {
  if (S.cfg && document.activeElement !== $('aj-nome')) {
    $('aj-nome').value = S.cfg.nome || ''; $('aj-moeda').value = S.cfg.moeda || 'CAD';
  }
  $('aj-t-desp').classList.toggle('on', S.ajTipo === 'despesa');
  $('aj-t-rec').classList.toggle('on', S.ajTipo === 'receita');
  var cats = ((S.cfg && S.cfg.cats) || []).filter(function (c) { return c.tipo === S.ajTipo; });
  $('aj-cats').innerHTML = cats.length ? cats.map(function (c) {
    return '<div class="linha"><span style="font-size:20px">' + esc(c.emoji) + '</span><span class="nm">' + esc(c.nome) +
      '<br><span class="small muted">' + (c.subs.length ? c.subs.length + ' subcategoria' + (c.subs.length > 1 ? 's' : '') : 'sem subcategorias') + '</span></span>' +
      '<button data-catup="' + c.id + '" aria-label="Subir">↑</button><button data-catedit="' + c.id + '">Editar</button></div>';
  }).join('') : '<div class="vazio">Nenhuma categoria.</div>';
  $('aj-codigo').textContent = codigoConvite();
  $('aj-novocod').style.display = souDono() ? '' : 'none';
  var uids = Object.keys(S.membros);
  $('aj-membros').innerHTML = uids.map(function (uid) {
    var p = S.perfis[uid] || {}, eu = uid === S.user.uid, dono = S.meta && S.meta.dono === uid;
    return '<div class="linha"><span class="nm">' + esc(p.nome || 'Membro') + (eu ? ' (você)' : '') +
      '<br><span class="small muted">' + esc(p.email || '') + (dono ? ' · criou a casa' : '') + '</span></span>' +
      (souDono() && !eu ? '<button class="perigo" data-remover="' + uid + '">Remover</button>' : '') + '</div>';
  }).join('');
  $('aj-conta').textContent = 'Conectado como ' + (S.user.email || '') + '.';
}

function salvarCasaAj() {
  var nome = $('aj-nome').value.trim();
  if (!nome) { toast('Informe o nome da casa'); return; }
  S.cfg.nome = nome; S.cfg.moeda = $('aj-moeda').value; _fmt = null;
  salvarCfg().then(function () { toast('Salvo ✓'); }, function () { toast('⚠️ Erro ao salvar'); });
}

// Modal de categoria
var EMOJIS = ['🏠','🛒','🚗','⛽','🩺','💊','🍽️','☕','🎉','✈️','📚','🐾','👕','💳','📦','👶','🎁','💼','💰','📈','🏋️','💡','📱','🧾','🔧','🎓','🍺','🎮','💇','🏦'];
var _edCat = null;
function abrirCat(id) {
  var orig = id ? catPorId(id) : null;
  _edCat = orig ? JSON.parse(JSON.stringify(orig)) : { id: rid(8), tipo: S.ajTipo, emoji: S.ajTipo === 'receita' ? '💰' : '📦', nome: '', subs: [], nova: true };
  desenharCat();
  $('modal').classList.add('on');
}
function desenharCat() {
  var c = _edCat;
  $('modal-box').innerHTML =
    '<h2>' + (c.nova ? 'Nova categoria' : 'Editar categoria') + '</h2>' +
    '<label>Nome</label><input id="mc-nome" maxlength="40" value="' + esc(c.nome) + '">' +
    '<label>Ícone</label><div class="chips" id="mc-emojis">' + EMOJIS.map(function (e) {
      return '<button class="chip' + (e === c.emoji ? ' on' : '') + '" data-emo="' + e + '">' + e + '</button>';
    }).join('') + '</div>' +
    '<label>Tipo</label><div class="chips"><button class="chip tipo-desp' + (c.tipo === 'despesa' ? ' on' : '') + '" data-mtipo="despesa">Despesa</button>' +
    '<button class="chip tipo-rec' + (c.tipo === 'receita' ? ' on' : '') + '" data-mtipo="receita">Receita</button></div>' +
    '<label>Subcategorias</label><div class="card lista-ed" style="margin-top:0">' +
    (c.subs.length ? c.subs.map(function (s, i) {
      return '<div class="linha"><input class="nm" data-subnome="' + i + '" maxlength="40" value="' + esc(s.nome) + '">' +
        '<button class="perigo" data-subdel="' + i + '">Excluir</button></div>';
    }).join('') : '<div class="small muted">Nenhuma subcategoria.</div>') +
    '<div class="linha"><input class="nm" id="mc-novasub" maxlength="40" placeholder="Nova subcategoria"><button id="mc-addsub">Adicionar</button></div></div>' +
    '<div class="erro" id="mc-erro"></div>' +
    '<button class="pri" id="mc-salvar">Salvar categoria</button>' +
    '<div class="row"><button class="link" id="mc-fechar">Cancelar</button>' +
    (c.nova ? '' : '<button class="perigo" id="mc-excluir" style="text-align:right">Excluir categoria</button>') + '</div>';
}
function lerCatInputs() {
  _edCat.nome = $('mc-nome').value;
  qsa('[data-subnome]').forEach(function (inp) { _edCat.subs[+inp.dataset.subnome].nome = inp.value; });
}
function fecharModal() { $('modal').classList.remove('on'); _edCat = null; }
function salvarCat() {
  lerCatInputs();
  var c = _edCat;
  c.nome = c.nome.trim();
  if (!c.nome) { $('mc-erro').textContent = 'Informe o nome da categoria.'; return; }
  c.subs = c.subs.map(function (s) { return { id: s.id, nome: s.nome.trim() }; }).filter(function (s) { return s.nome; });
  var nova = c.nova; delete c.nova;
  if (nova) S.cfg.cats.push(c);
  else S.cfg.cats = S.cfg.cats.map(function (x) { return x.id === c.id ? c : x; });
  S.ajTipo = c.tipo;
  fecharModal(); render();
  salvarCfg().then(function () { toast('Categoria salva ✓'); }, function () { toast('⚠️ Erro ao salvar'); });
}
function excluirCat() {
  var c = _edCat;
  var usados = Object.keys(S.lanc).filter(function (k) { return S.lanc[k].c === c.id; }).length;
  var msg = 'Excluir a categoria "' + (c.nome || '') + '"?' + (usados ? '\n\n' + usados + ' lançamento(s) ficarão como "Sem categoria".' : '');
  if (!confirm(msg)) return;
  S.cfg.cats = S.cfg.cats.filter(function (x) { return x.id !== c.id; });
  fecharModal(); render();
  salvarCfg().then(function () { toast('Categoria excluída'); });
}
function subirCat(id) {
  var cs = S.cfg.cats, i = -1;
  for (var k = 0; k < cs.length; k++) if (cs[k].id === id) i = k;
  var tipo = cs[i].tipo, j = i - 1;
  while (j >= 0 && cs[j].tipo !== tipo) j--;
  if (j < 0) return;
  var t = cs[i]; cs[i] = cs[j]; cs[j] = t;
  render(); salvarCfg();
}

// Convite / membros
function copiar(txt) {
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(txt).then(function () { toast('Código copiado'); }, function () { toast('Toque e segure o código para copiar'); });
  else toast('Toque e segure o código para copiar');
}
function compartilhar() {
  var txt = 'Convite para a casa no HomeVault:\n' + codigoConvite() + '\n\nAbra ' + location.href.split('#')[0].split('?')[0] +
    ', crie sua conta e toque em "Tenho um convite". Vou te passar a senha da casa separadamente.';
  if (navigator.share) navigator.share({ text: txt }).catch(function () {});
  else copiar(txt);
}
function novoCodigo() {
  if (!confirm('Gerar um novo código? O código atual deixa de funcionar para novos convites. Quem já está na casa não é afetado.')) return;
  db.ref('casas/' + S.casa + '/convite').set(rid(24)).then(function () { toast('Novo código gerado'); }, function () { toast('⚠️ Erro'); });
}
function removerMembro(uid) {
  var p = S.perfis[uid] || {};
  if (!confirm('Remover ' + (p.nome || 'este membro') + ' da casa? A pessoa perde o acesso aos dados.\n\nDica: depois, gere um novo código de convite.')) return;
  Promise.all([
    db.ref('casas/' + S.casa + '/membros/' + uid).remove(),
    db.ref('casas/' + S.casa + '/dados/perfis/' + uid).remove()
  ]).then(function () { toast('Membro removido'); }, function () { toast('⚠️ Erro ao remover'); });
}

// Backup
function baixar(nome, tipo, conteudo) {
  var blob = new Blob([conteudo], { type: tipo });
  try {
    var arq = new File([blob], nome, { type: tipo });
    if (navigator.canShare && navigator.canShare({ files: [arq] }) && /iPhone|iPad|Android/i.test(navigator.userAgent)) {
      navigator.share({ files: [arq], title: nome }).catch(function () {});
      return;
    }
  } catch (e) {}
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = nome;
  document.body.appendChild(a); a.click();
  setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
function exportarJSON() {
  var dados = {
    app: 'HomeVault', formato: 1, exportado: new Date().toISOString(),
    casa: { nome: S.cfg.nome, moeda: S.cfg.moeda }, categorias: S.cfg.cats,
    lancamentos: Object.keys(S.lanc).map(function (k) { return S.lanc[k]; })
  };
  baixar('homevault-backup-' + hojeISO() + '.json', 'application/json', JSON.stringify(dados, null, 1));
}
function exportarCSV() {
  var q = function (s) { return '"' + String(s == null ? '' : s).replace(/"/g, '""') + '"'; };
  var linhas = ['Data;Tipo;Categoria;Subcategoria;Descrição;Valor'];
  Object.keys(S.lanc).map(function (k) { return S.lanc[k]; }).sort(function (a, b) { return a.dt < b.dt ? -1 : 1; }).forEach(function (l) {
    var c = catPorId(l.c), s = subPorId(c, l.s);
    linhas.push([l.dt, l.t === 'receita' ? 'Receita' : 'Despesa', q(c ? c.nome : ''), q(s ? s.nome : ''), q(l.d),
      (l.t === 'receita' ? '' : '-') + centParaTexto(l.v)].join(';'));
  });
  baixar('homevault-' + hojeISO() + '.csv', 'text/csv;charset=utf-8', '﻿' + linhas.join('\r\n'));
}
function importarJSON(arquivo) {
  var r = new FileReader();
  r.onload = function () {
    var d;
    try { d = JSON.parse(r.result); } catch (e) { toast('Arquivo inválido'); return; }
    if (!d || d.app !== 'HomeVault' || !Array.isArray(d.lancamentos)) { toast('Não é um backup do HomeVault'); return; }
    if (!confirm('Restaurar ' + d.lancamentos.length + ' lançamento(s) deste backup?\n\nLançamentos com o mesmo identificador serão substituídos; os demais serão mantidos. Categorias que não existem serão adicionadas.')) return;
    var ids = {}; S.cfg.cats.forEach(function (c) { ids[c.id] = true; });
    var novas = (d.categorias || []).filter(function (c) { return c && c.id && !ids[c.id]; });
    if (novas.length) S.cfg.cats = S.cfg.cats.concat(novas);
    var ps = [salvarCfg()];
    d.lancamentos.forEach(function (l) {
      if (l && l.v > 0 && /^\d{4}-\d{2}-\d{2}$/.test(l.dt)) ps.push(salvarLanc(l));
    });
    Promise.all(ps).then(function () { toast('Backup restaurado ✓'); }, function () { toast('⚠️ Parte do backup não foi salva'); });
  };
  r.readAsText(arquivo);
}

// ───────────────────────── eventos ─────────────────────────
function ligarEventos() {
  $('tab-entrar').onclick = function () { setModoCriar(false); };
  $('tab-criar').onclick = function () { setModoCriar(true); };
  $('au-btn').onclick = enviarAuth;
  $('au-senha').onkeydown = function (e) { if (e.key === 'Enter') enviarAuth(); };
  $('au-esqueci').onclick = esqueci;

  $('tab-nova').onclick = function () { $('tab-nova').classList.add('on'); $('tab-convite').classList.remove('on'); $('box-nova').style.display = ''; $('box-convite').style.display = 'none'; };
  $('tab-convite').onclick = function () { $('tab-convite').classList.add('on'); $('tab-nova').classList.remove('on'); $('box-convite').style.display = ''; $('box-nova').style.display = 'none'; };
  $('nc-btn').onclick = criarCasa;
  $('cv-btn').onclick = entrarConvite;
  $('ul-btn').onclick = desbloquear;
  $('ul-senha').onkeydown = function (e) { if (e.key === 'Enter') desbloquear(); };
  qsa('[data-acao="sair"]').forEach(function (b) { b.onclick = sair; });

  qsa('#nav button').forEach(function (b) { b.onclick = function () { mostrar(b.dataset.ir); }; });

  qsa('[data-tipo]').forEach(function (b) {
    b.onclick = function () { if (S.lc.tipo !== b.dataset.tipo) { S.lc.tipo = b.dataset.tipo; S.lc.cat = null; S.lc.sub = null; } renderLancar(); };
  });
  $('lc-cats').onclick = function (e) {
    var b = e.target.closest('[data-cat]'); if (!b) return;
    if (S.lc.cat !== b.dataset.cat) S.lc.sub = null;
    S.lc.cat = b.dataset.cat; renderLancar();
  };
  $('lc-subs').onclick = function (e) {
    var b = e.target.closest('[data-sub]'); if (!b) return;
    S.lc.sub = S.lc.sub === b.dataset.sub ? null : b.dataset.sub; renderLancar();
  };
  $('lc-btn').onclick = salvarForm;
  $('lc-cancelar').onclick = function () { resetForm(); mostrar('hist'); };
  $('lc-excluir').onclick = function () {
    if (!confirm('Excluir este lançamento?')) return;
    excluirLanc(S.lc.editando).catch(function () { toast('⚠️ Erro ao excluir'); });
    resetForm(); mostrar('hist'); toast('Lançamento excluído');
  };

  qsa('[data-mes]').forEach(function (b) { b.onclick = function () { S.mes = somaMes(S.mes, +b.dataset.mes); render(); }; });
  $('hi-busca').oninput = renderHist;
  $('hi-cat').onchange = renderHist;
  $('hi-lista').onclick = function (e) { var it = e.target.closest('[data-ed]'); if (it) editar(it.dataset.ed); };
  $('rs-cats').onclick = function (e) { var l = e.target.closest('.catlin'); if (l) l.classList.toggle('aberta'); };

  $('aj-salvar').onclick = salvarCasaAj;
  $('aj-t-desp').onclick = function () { S.ajTipo = 'despesa'; renderAjustes(); };
  $('aj-t-rec').onclick = function () { S.ajTipo = 'receita'; renderAjustes(); };
  $('aj-novacat').onclick = function () { abrirCat(null); };
  $('aj-cats').onclick = function (e) {
    var ed = e.target.closest('[data-catedit]'); if (ed) { abrirCat(ed.dataset.catedit); return; }
    var up = e.target.closest('[data-catup]'); if (up) subirCat(up.dataset.catup);
  };
  $('aj-copiar').onclick = function () { copiar(codigoConvite()); };
  $('aj-compart').onclick = compartilhar;
  $('aj-novocod').onclick = novoCodigo;
  $('aj-membros').onclick = function (e) { var b = e.target.closest('[data-remover]'); if (b) removerMembro(b.dataset.remover); };
  $('aj-exp-json').onclick = exportarJSON;
  $('aj-exp-csv').onclick = exportarCSV;
  $('aj-imp').onclick = function () { $('aj-imp-arq').click(); };
  $('aj-imp-arq').onchange = function () { if (this.files[0]) importarJSON(this.files[0]); this.value = ''; };
  $('aj-bloquear').onclick = function () { if (confirm('Bloquear? Será preciso digitar a senha da casa para abrir de novo neste aparelho.')) bloquear(); };

  $('modal').onclick = function (e) {
    if (e.target.id === 'modal') { fecharModal(); return; }
    var t = e.target;
    if (t.closest('[data-emo]')) { lerCatInputs(); _edCat.emoji = t.closest('[data-emo]').dataset.emo; desenharCat(); }
    else if (t.closest('[data-mtipo]')) { lerCatInputs(); _edCat.tipo = t.closest('[data-mtipo]').dataset.mtipo; desenharCat(); }
    else if (t.closest('[data-subdel]')) { lerCatInputs(); _edCat.subs.splice(+t.closest('[data-subdel]').dataset.subdel, 1); desenharCat(); }
    else if (t.id === 'mc-addsub') {
      lerCatInputs();
      var n = $('mc-novasub').value.trim();
      if (n) { _edCat.subs.push({ id: rid(8), nome: n }); desenharCat(); $('mc-novasub').focus(); }
    }
    else if (t.id === 'mc-salvar') salvarCat();
    else if (t.id === 'mc-fechar') fecharModal();
    else if (t.id === 'mc-excluir') excluirCat();
  };
  $('modal').onkeydown = function (e) { if (e.key === 'Enter' && e.target.id === 'mc-novasub') { e.preventDefault(); $('mc-addsub').click(); } };
}

// Teste interno (usado só pelos testes automatizados)
window.__HV = { S: S, lerValor: lerValor, cifrar: cifrar, decifrar: decifrar, derivarChave: derivarChave, lerConvite: lerConvite };

iniciar();
})();
