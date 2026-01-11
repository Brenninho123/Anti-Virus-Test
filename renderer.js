const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCAN = './scan';
const QUAR = './quarantine';
const LOG = './logs';

[SCAN, QUAR, LOG].forEach(d => fs.mkdirSync(d, { recursive: true }));

function log(msg) {
  document.getElementById('log').innerText += msg + '\n';
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function scan() {
  log('🔍 Iniciando scan...');
  fs.readdirSync(SCAN).forEach(f => {
    const full = path.join(SCAN, f);
    if (!fs.statSync(full).isFile()) return;
    const content = fs.readFileSync(full, 'utf8');
    if (content.includes('eval(')) {
      fs.renameSync(full, path.join(QUAR, f));
      log('⚠️ Malware detectado: ' + f);
    } else {
      log('✅ Limpo: ' + f);
    }
  });
}

function monitor() {
  log('👁 Monitoramento ativo...');
  fs.watch(SCAN, (_, f) => {
    if (f) scan();
  });
}

function listQ() {
  log('📦 Quarentena:');
  fs.readdirSync(QUAR).forEach(f => log(' - ' + f));
}