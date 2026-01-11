const { app, BrowserWindow } = require('electron');
const path = require('path');

let splash;
let mainWin;

function createWindows() {
  splash = new BrowserWindow({
    width: 400,
    height: 200,
    frame: false,
    alwaysOnTop: true
  });

  splash.loadFile('splash.html');

  mainWin = new BrowserWindow({
    width: 900,
    height: 550,
    show: false,
    title: 'Antivírus',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  mainWin.loadFile('index.html');

  setTimeout(() => {
    splash.close();
    mainWin.show();
  }, 2000);
}

app.whenReady().then(createWindows);