/*
 *  Power BI Visual CLI
 *
 *  Copyright (c) Microsoft Corporation
 *  All rights reserved.
 *  MIT License
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the ""Software""), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */
"use strict";

let fs = require('fs-extra');
let path = require('path');
let os = require('os');
let exec = require('child_process').execSync;
let async = require('async');
let JSZip = require('jszip');
let request = require('request');
console.log(__dirname);
let confPath = '../../config.json';
let config = require(confPath);

let FileSystem = require('../helpers/FileSystem.js');

const tempPath = FileSystem.getTempPath();
const startPath = process.cwd();

function removeCertFiles(certPath, keyPath, pfxPath) {
    try {
        fs.unlinkSync(certPath);
    } catch (e) {
        if (!e.message.indexOf("no such file or directory")) {
            throw e;
        }
    }
    try {
        fs.unlinkSync(keyPath);
    } catch (e) {
        if (!e.message.indexOf("no such file or directory")) {
            throw e;
        }
    }
    try {
        fs.unlinkSync(pfxPath);
    } catch (e) {
        if (!e.message.indexOf("no such file or directory")) {
            throw e;
        }
    }
}

describe("E2E - pbiviz --create-cert", () => {
    beforeEach(() => {
        FileSystem.resetTempDirectory();
        process.chdir(tempPath);
        FileSystem.runPbiviz('', '--create-cert');
    });

    describe("pbiviz", () => {
        const subject = "localhost";
        const keyLength = 2048;
        const algorithm = "sha256";
        const certName = "CN=localhost";
        const validPeriod = 180;
        const msInOneDay = 86400000;

        it("pbiviz --create-cert command should generate certificate", (done) => {
            let platform = os.platform();
            let certPath = path.join(__dirname, "../../", config.server.certificate);
            let keyPath = path.join(__dirname, "../../", config.server.privateKey);
            let pfxPath = path.join(__dirname, "../../", config.server.pfx);

            // for travis and appveor win server 2016 
            let certExists = fs.existsSync(certPath);
            let keyExists = fs.existsSync(keyPath);
            let pfxExists = fs.existsSync(pfxPath);

            let win7result;
            let win8result;

            let commonResult = certExists && keyExists || pfxExists;

            // check enviroment using only
            // check generating cert for win7 and appveor win server 2012
            if (platform === "win32") {
                removeCertFiles(certPath, keyPath, pfxPath);

                let osVersion = os.release().split(".");                
                let startCmd = "openssl";
                let createCertCommand =
                    `  req -newkey rsa:${keyLength}` +
                    ` -nodes` +
                    ` -keyout ${keyPath}` +
                    ` -x509 ` +
                    ` -days ${validPeriod} ` +
                    ` -out ${certPath} ` +
                    ` -subj "/CN=${subject}"`;
                exec(`${startCmd} ${createCertCommand}`);

                let certExists = fs.existsSync(certPath);
                let keyExists = fs.existsSync(keyPath);
                let pfxExists = fs.existsSync(pfxPath);
                win7result = certExists && keyExists || pfxPath;

                expect(win7result).toBeTruthy();

                // server 2012
                {
                    removeCertFiles(certPath, keyPath, pfxPath);

                    let passphrase = Math.random().toString().substring(2);
                    let startCmd = "powershell";
                    createCertCommand = `$cert = ('Cert:\\CurrentUser\\My\\' + (` +
                    `   New-SelfSignedCertificate ` +
                    `       -DnsName localhost ` +
                    `       -CertStoreLocation Cert:\\CurrentUser\\My ` +
                    `   | select Thumbprint | ` +
                    `   ForEach-Object { $_.Thumbprint.ToString() }).toString()); ` +
                    `   Export-PfxCertificate -Cert $cert` +
                    `       -FilePath '${pfxPath}' ` +
                    `       -Password (ConvertTo-SecureString -String '${passphrase}' -Force -AsPlainText)`;

                    exec(`${startCmd} "${createCertCommand}"`);

                    let certExists = fs.existsSync(certPath);
                    let keyExists = fs.existsSync(keyPath);
                    let pfxExists = fs.existsSync(pfxPath);
                    win8result = certExists && keyExists || pfxPath;

                    expect(win8result).toBeTruthy();
                }
            }
            expect(commonResult || win7result || win8result).toBeTruthy();
            done();
        });
    });
});
