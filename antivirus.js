const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const chalk = require('chalk'); // cores no console

//////////////////// CONFIG ////////////////////
const SCAN_PATH = './scan';
const QUARANTINE = './quarantine';
const LOG_DIR = './logs';
[SCAN_PATH, QUARANTINE, LOG_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));
const LOG_FILE = path.join(LOG_DIR, 'log-' + Date.now() + '.json');

const signatures = ["eval(", "child_process", "new Function(", "while(true)", "process.exit(", "document.cookie"];
const hashDB = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"];

//////////////////// LOG ////////////////////
function log(type, file, extra) {
  const entry = { time: new Date().toISOString(), type, file, extra };
  fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
  console.log(chalk.blue(`[${type}]`) + ' ' + file, extra ? extra : '');
}

//////////////////// HASH ////////////////////
function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

//////////////////// QUARENTENA ////////////////////
function quarantine(file) {
  const dest = path.join(QUARANTINE, path.basename(file));
  fs.renameSync(file, dest);
  log('QUARANTINE', dest);
}

function restore(fileName) {
  const src = path.join(QUARANTINE, fileName);
  const dest = path.join(SCAN_PATH, fileName);
  if (!fs.existsSync(src)) return console.log(chalk.red('❌ Arquivo não encontrado na quarentena'));
  fs.renameSync(src, dest);
  log('RESTORE', dest);
}

function listQuarantine() { return fs.readdirSync(QUARANTINE); }

function heuristic(content) {
  let score = 0;
  if (content.includes('eval(')) score += 3;
  if (content.includes('child_process')) score += 4;
  if (content.includes('while(true)')) score += 2;
  if (content.includes('process.exit')) score += 1;
  return score;
}

function scanFile(file) {
  try {
    const ext = path.extname(file);
    if (!['.js','.txt','.html','.json'].includes(ext)) return;
    const hash = sha256(file);
    if (hashDB.includes(hash)) { log('MALWARE_HASH', file); quarantine(file); return; }
    const content = fs.readFileSync(file, 'utf8');
    const sigs = signatures.filter(s => content.includes(s));
    const risk = heuristic(content);
    if (sigs.length>0 || risk>=5) { log('MALWARE', file,{signatures:sigs,risk}); quarantine(file); return; }
    log('CLEAN', file, {risk});
  } catch(e){ log('ERROR', file,{message:e.message}); }
}

function scanDir(dir){ fs.readdirSync(dir).forEach(item => { const full=path.join(dir,item); const stat=fs.statSync(full); if(stat.isDirectory()) scanDir(full); else scanFile(full); }); }

function monitor(){ log('INFO','Monitoramento iniciado'); fs.watch(SCAN_PATH,{recursive:true},(_,file)=>{ if(!file) return; const full=path.join(SCAN_PATH,file); if(fs.existsSync(full)) scanFile(full); }); }

//////////////////// CLI ////////////////////
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function splash() {
  console.clear();
  console.log(chalk.green.bold(`
████████╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗
╚══██╔══╝██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║
   ██║   ███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██║   ██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║   ██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
`));
  console.log(chalk.yellow('🛡 Antivirus JS - Iniciando...'));
}

function menu(){
  console.log(chalk.cyan(`
1) Scan completo
2) Monitoramento em tempo real
3) Listar quarentena
4) Restaurar arquivo
5) Sair
`));
  rl.question('Escolha: ', op=>{
    if(op==='1'){ scanDir(SCAN_PATH); menu(); }
    else if(op==='2'){ monitor(); }
    else if(op==='3'){ const files=listQuarantine(); console.log(files.length ? files : chalk.gray('Quarentena vazia')); menu(); }
    else if(op==='4'){ rl.question('Nome do arquivo: ', name=>{ restore(name); menu(); }); }
    else{ rl.close(); }
  });
}

splash();
setTimeout(menu, 1500); // splash animado 1,5s