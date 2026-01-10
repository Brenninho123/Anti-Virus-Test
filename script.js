const fs = require('fs');
const path = require('path');

const folderPath = path.join(__dirname, 'data');

const malwareSignatures = [
    'eval(',
    'require("child_process")',
    'malicious_code_3'
];