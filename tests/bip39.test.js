const Bip39 = require('../lib');
const crypto = require('crypto');
const bip39 = new Bip39();

describe('BIP39 Implementation Tests', () => {
    test('generateMnemonic generates a mnemonic with correct word count', () => {
        const wordCounts = [12, 15, 21, 24];
        wordCounts.forEach(count => {
            let options = {
                numberOfWords: count,
            };
            const mnemonic = bip39.generateMnemonic(options);
            expect(mnemonic.split(' ').length).toBe(count);
        });
    });

    test('generateMnemonic throws error on invalid word count', () => {
        expect(() => {
            bip39.generateMnemonic({ numberOfWords: 10 });
        }).toThrow('Invalid word count');
    });

    test('validateBIP39Mnemonic returns true for valid mnemonic', () => {
        let options = {
            numberOfWords: 12,
        };
        const validMnemonic = bip39.generateMnemonic(options);
        expect(bip39.validateBIP39Mnemonic(validMnemonic)).toBe(true);
    });

    test('validateBIP39Mnemonic returns false for invalid mnemonic', () => {
        const invalidMnemonic = 'this is not a valid mnemonic';
        expect(bip39.validateBIP39Mnemonic(invalidMnemonic)).toBe(false);
    });

    test('mnemonicToSeed generates seed correctly', () => {
        let options = {
            numberOfWords: 12,
        };
        const mnemonic = bip39.generateMnemonic(options);
        const seedOptions = { mnemonic, passphrase: 'test-passphrase' };
        const seed = bip39.mnemonicToSeed(seedOptions);
        expect(seed).toBeDefined();
        expect(seed.length).toBe(64);
    });

    test('getEntropyBits returns correct entropy bits for given word count', () => {
        const wordCountToEntropyBits = {
            12: 128,
            15: 160,
            21: 224,
            24: 256,
        };
        Object.entries(wordCountToEntropyBits).forEach(([wordCount, entropyBits]) => {
            let options = { numberOfWords: parseInt(wordCount) };
            expect(bip39.generateEntropyBits(options)).toBe(entropyBits);
        });
    });

    test('getEntropyBits throws error on invalid word count', () => {
        expect(() => {
            bip39.generateEntropyBits({ numberOfWords: 11 });
        }).toThrow('Invalid word count');
    });

    test('calculateChecksumBits returns a binary string of the correct length', () => {
        const entropy = Buffer.from('00000000000000000000000000000000', 'hex');
        const hash = crypto.createHash('sha256').update(entropy).digest();
        const checksumBits = 4;
        const checksum = bip39.calculateChecksumBits(hash, checksumBits);
        expect(checksum.length).toBe(checksumBits);
        expect(/^[01]+$/.test(checksum)).toBe(true);
    });

    test('bytesToBinary and binaryToBytes conversion round trip', () => {
        const originalBytes = [0, 127, 255];
        const binaryString = bip39.bytesToBinary(originalBytes);
        const convertedBytes = bip39.binaryToBytes(binaryString);
        expect(convertedBytes).toEqual(originalBytes);
    });

    test('mnemonicToSeed throws error for invalid mnemonic', () => {
        const options = { mnemonic: 'invalid mnemonic string', passphrase: 'test-passphrase' };
        expect(() => bip39.mnemonicToSeed(options)).toThrow('Invalid mnemonic.');
    });

    test('generateMnemonic produces unique mnemonics', () => {
        const mnemonicSet = new Set();
        const iterations = 1000;
        for (let i = 0; i < iterations; i++) {
            const options = { numberOfWords: 12 };
            mnemonicSet.add(bip39.generateMnemonic(options));
        }
        expect(mnemonicSet.size).toBe(iterations);
    });

    test('mnemonicToSeed generates consistent seed for same mnemonic and passphrase', () => {
        const options = { numberOfWords: 12 };
        const mnemonic = bip39.generateMnemonic(options);
        const seedOptions = { mnemonic, passphrase: 'test-passphrase' };
        const seed1 = bip39.mnemonicToSeed(seedOptions);
        const seed2 = bip39.mnemonicToSeed(seedOptions);
        expect(Buffer.compare(seed1, seed2)).toBe(0);
    });

    describe('BIP39 Encryption and Initialization Tests', () => {

        test('initialize with new mnemonic', () => {
            const options = {
                password: 'test-password',
                numberOfWords: 12,
            };
            bip39.initialize(options);
            expect(bip39.initialized).toBe(true);
        });

        test('initialize with provided mnemonic', () => {
            const options = {
                password: 'test-password',
                mnemonic: 'diamond umbrella flame various road nerve cage volcano draft knife nasty motion',
            };
            bip39.initialize(options);
            expect(bip39.initialized).toBe(true);
        });

        test('encrypt mnemonic and seed', () => {
            const options = {
                password: 'test-password',
                numberOfWords: 12,
            };
            bip39.initialize(options);
            const encryptedPassphrase = bip39.LoadEncryptedPassphrase();
            const encryptedSeed = bip39.LoadEncryptedSeed();
            expect(encryptedPassphrase).toBeDefined();
            expect(encryptedSeed).toBeDefined();
        });

        test('decrypt passphrase', () => {
            const options = {
                password: 'test-password',
                numberOfWords: 12,
            };
            bip39.initialize(options);
            const decryptedMnemonic = bip39.decrypt({ unlock: 'passphrase', password: 'test-password' });
            expect(decryptedMnemonic).toBeDefined();
            expect(bip39.validateBIP39Mnemonic(decryptedMnemonic)).toBe(true);
        });

        test('decrypt with wrong unlock type throws error', () => {
            const options = {
                unlock: 'wrongType',
                password: 'test-password',
            };
            expect(() => {
                bip39.decrypt(options);
            }).toThrow('unlock must be either passphrase or seed');
        });

        test('decrypt seed', () => {
            const options = {
                password: 'test-password',
                numberOfWords: 12,
            };
            bip39.initialize(options);
            const decryptedSeed = bip39.decrypt({ unlock: 'seed', password: 'test-password' });
            expect(decryptedSeed).toBeDefined();
        });

        test('initialize without password throws error', () => {
            const options = { numberOfWords: 12 };
            expect(() => bip39.initialize(options)).toThrow('Password must be provided');
        });
    });
});
