const fs = require('fs');
const tls = require('tls');
const util = require('util');
const child_process = require('child_process');

const writeFile = util.promisify(fs.writeFile);
const exec = util.promisify(child_process.exec);

function printUsage() {
    console.log('USAGE:');
    console.log('    node download-certs.js [OPTIONS...] <HOST:PORT>...');
    console.log('');

    console.log('OPTIONS:');
    console.log('    --insecure: Se definido, o client não irá rejeitar conexões que falharam na verificação TLS ao utilizar a CA padrão do Node.js');
    console.log('    --server-name <hostname>: Hostname SNI requerido pelo servidor');
    console.log('    --jks: Se definido, gera uma nova truststore contendo os certificados do servidor (necessita do keytool disponível no PATH)');
    console.log('');

    console.log('EXAMPLES:');
    console.log('    node download-certs.js www.microsoft.com');
    console.log('    node download-certs.js --server-name google.com google.com');
    console.log('    node download-certs.js --jks www.microsoft.com:443 github.com');
    console.log('    node download-certs.js --insecure --server-name my-sni-domain.com 127.0.0.1:443');
}

class CliParserError extends Error {
    constructor({ message }) {
        super(message);

        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }
}

class NoArgumentsProvidedError extends CliParserError {
    constructor() {
        super('no arguments provided');

        this.code = 'CLI_PARSER_NO_ARGS_PROVIDED_ERR';
        this.data = {
            systemCode: 2,
        };
    }
}

class NoRequiredArgumentValueProvidedError extends CliParserError {
    constructor({ arg }) {
        super({ message: `no required value provided for argument "${arg}"` });

        this.code = 'CLI_PARSER_NO_REQUIRED_ARGUMENT_VALUE_PROVIDED_ERR';
        this.data = {
            arg,
            systemCode: 3,
        };
    }
}

class UnrecognizedOptionError extends CliParserError {
    constructor({ lexeme }) {
        super({ message: `unrecognized option "${lexeme}"` });

        this.code = 'CLI_PARSER_UNRECOGNIZED_OPTION_ERR';
        this.data = {
            lexeme,
            systemCode: 4,
        };
    }
}

class CliParser {

    constructor() {
        this.args = process.argv.slice(2);
        this.offset = 0;
    }

    parse() {
        const options = this.parseOptions();
        const args = this.parseArgs();

        if (!options['help'] && args.length === 0) {
            throw new NoArgumentsProvidedError();
        }

        return { options, args };
    }

    parseOptions() {
        const options = {};
        for (let { option, value } of this.parseOption()) {
            options[option] = value;
        }
        return options;
    }

    *parseOption() {
        while (!this.eof()) {
            let arg = this.currentArgument();
            if (!arg.startsWith('--')) {
                break;
            }

            const option = arg.slice(2);

            if (option === 'help') {
                this.advance();

                yield { option, value: true };
                continue;
            }

            if (option === 'server-name') {
                this.advance();
                if (this.eof()) {
                    throw new NoRequiredArgumentValueProvidedError({ arg });
                }

                const value = this.currentArgument();

                this.advance();

                yield { option, value };
                continue;
            }

            if (option === 'insecure') {
                this.advance();

                yield { option, value: true };
                continue;
            }

            if (option === 'jks') {
                this.advance();

                yield { option, value: true };
                continue;
            }

            throw new UnrecognizedOptionError({ lexeme: arg });
        }
    }

    parseArgs() {
        return this.args.slice(this.offset);
    }

    currentArgument() {
        return this.args[this.offset];
    }

    advance() {
        this.offset++;
    }

    eof() {
        return this.offset >= this.args.length;
    }
}

function tlsConnect(connectionOptions) {
    return new Promise(function (resolve, reject) {
        const tlsSocket = tls.connect(connectionOptions, function () {
            resolve(tlsSocket);
        });
        tlsSocket.on('error', reject);
    });
}

function collectCerts(rootCert) {
    const certs = [];
    let cert = rootCert;
    for (; cert !== null && cert !== cert.issuerCertificate; cert = cert.issuerCertificate) {
        certs.push(cert);
    }
    certs.push(cert);
    return certs;
}

function derToPem(derCert) {
    const header = '-----BEGIN CERTIFICATE-----\n';
    const footer = '-----END CERTIFICATE-----';
    return header + derCert.toString('base64') + footer;
}

async function handleConnection(tlsSocket, cliContext, downloadParam) {
    const detailed = true;
    let rootCert = tlsSocket.getPeerCertificate(detailed);
    if (rootCert === null) {
        throw new Error('could not get server certificate');
    }

    const certs = collectCerts(rootCert);

    const writeFilePromises = [];
    const pemCerts = [];
    for (let i = 0; i < certs.length; i++) {
        const cert = certs[i];
        const pem = derToPem(cert.raw);
        const pemFileName = `${downloadParam.host}.${i}.pem`;

        pemCerts.push(pem);
        writeFilePromises.push(writeFile(pemFileName, pem));
    }
    const fullChainPem = pemCerts.join('');
    writeFilePromises.push(writeFile(`${downloadParam.host}.fullchain.pem`, fullChainPem));

    await Promise.all(writeFilePromises);

    const truststoreFileName = 'truststore.jks';
    const password = 'changeit';
    const keytoolPromises = [];
    if (cliContext.options['jks']) {
        const jksFileName = `${downloadParam.host}.jks`;
        for (let i = 0; i < certs.length; i++) {
            const alias = `${downloadParam.host}.${i}`;
            const pemFileName = `${alias}.pem`;

            // TODO BUG: stdout não está sendo conectado. Promisificação está ok?
            keytoolPromises.push(exec(`keytool -importcert -noprompt -file ${pemFileName} -alias ${alias} -keystore ${jksFileName} -storepass ${password}`));
            keytoolPromises.push(exec(`keytool -importcert -noprompt -file ${pemFileName} -alias ${alias} -keystore ${truststoreFileName} -storepass ${password}`));
        }
    }
    await Promise.all(keytoolPromises);
}

function parseArgs() {
    const cliParser = new CliParser();

    try {
        return cliParser.parse();
    } catch (err) {
        let errorCode;
        if (err instanceof CliParserError) {
            console.error(`\u001b[91merror: ${err.message}.\u001b[0m\n`);
            errorCode = err.systemCode;
        } else {
            console.error('\u001b[91merror:\u001b[0m', err);
            errorCode = 1;
        }
        printUsage();
        process.exit(errorCode);
    }
}

async function downloadCertificates(cliContext, downloadParam) {
    let tlsSocket;
    try {
        tlsSocket = await tlsConnect(downloadParam.connectionOptions);
    } catch (err) {
        console.error(`\u001b[91merror: could not get certificates. \u001b[96mdownloadParams=${JSON.stringify(downloadParam, null, 4)}\u001b[0m\n`, err);
        return { success: false, downloadParam };
    }

    try {
        await handleConnection(tlsSocket, cliContext, downloadParam);
    } catch (err) {
        console.error(`\u001b[91merror: could not get certificates. \u001b[96mdownloadParams=${JSON.stringify(downloadParam, null, 4)}\u001b[0m\n`, err);
        return { success: false, downloadParam };
    } finally {
        tlsSocket.destroy();
    }

    return { success: true, downloadParam };
}

async function main() {
    const cliContext = parseArgs();
    if (cliContext.options['help']) {
        printUsage();
        process.exit(0);
    }

    // Converte os argumentos (hostnames) em objetos {host, port, connectionOptions}
    // connectionOptions tls.connect
    const downloadParams = cliContext.args.map(hostname => {
        const parts = hostname.split(':');
        const host = parts[0];

        // define a porta padrão 443 caso o hostname não tenha sido definido no formato 'host:port'
        const port = (parts.length > 1) ? parts[1] : '443';

        // Define o objeto que descreve as opções de tls.connect
        const connectionOptions = { host, port };

        if (cliContext.options['server-name']) {
            connectionOptions.servername = cliContext.options['server-name'];
        }

        if (cliContext.options['insecure']) {
            connectionOptions.rejectUnauthorized = false;
        }

        return { host, port, connectionOptions };
    });


    const downloadPromises = downloadParams.map(downloadParam => downloadCertificates(cliContext, downloadParam));
    const responses = await Promise.all(downloadPromises);
    const failed = responses.filter(outcome => outcome.success === false).length > 0;
    if (failed) {
        process.exit(1);
    }
}

main().catch(console.error);

