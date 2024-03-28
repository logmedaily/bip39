const {
    generateMnemonic,
    validateBIP39Mnemonic,
    mnemonicToSeed,
    getEntropyBits,
    calculateChecksumBits,
    bytesToBinary,
    binaryToBytes,
    generateEntropyBits,
} = require('../lib');
const crypto = require('crypto');


describe('BIP39 Implementation Tests', () => {

    test('generateMnemonic generates a mnemonic with correct word count', () => {
        const wordCounts = [12, 15, 21, 24];
        wordCounts.forEach(count => {
            const mnemonic = generateMnemonic(count);
            console.log(mnemonic);
            expect(mnemonic.split(' ').length).toBe(count);
        });
    });

    test('generateMnemonic throws error on invalid word count', () => {
        expect(() => {
            generateMnemonic(10);
        }).toThrow('Invalid word count');
    });

    test('validateBIP39Mnemonic returns true for valid mnemonic', () => {
        const validMnemonic = generateMnemonic(12);
        expect(validateBIP39Mnemonic(validMnemonic)).toBe(true);
    });

    test('validateBIP39Mnemonic returns false for invalid mnemonic', () => {
        const invalidMnemonic = 'this is not a valid mnemonic';
        expect(validateBIP39Mnemonic(invalidMnemonic)).toBe(false);
    });

    test('mnemonicToSeed generates seed correctly', () => {
        const mnemonic = generateMnemonic(12);
        const seed = mnemonicToSeed(mnemonic, 'test-passphrase');
        expect(seed).toBeDefined();
        expect(seed.length).toBe(64); // Check if the seed length is correct
    });

    test('getEntropyBits returns correct entropy bits for given word count', () => {
        const wordCountToEntropyBits = {
            12: 128,
            15: 160,
            21: 224,
            24: 256,
        };
        for (const [wordCount, entropyBits] of Object.entries(wordCountToEntropyBits)) {
            expect(getEntropyBits(parseInt(wordCount))).toBe(entropyBits);
        }
    });

    test('getEntropyBits throws error on invalid word count', () => {
        expect(() => {
            getEntropyBits(11);
        }).toThrow('Invalid word count');
    });

    test('calculateChecksumBits returns a binary string of the correct length', () => {
        const entropy = Buffer.from('00000000000000000000000000000000', 'hex');
        const hash = crypto.createHash('sha256').update(entropy).digest();
        const checksumBits = 4;
        const checksum = calculateChecksumBits(hash, checksumBits);
        expect(checksum.length).toBe(checksumBits);
        expect(/^[01]+$/.test(checksum)).toBe(true);
    });


    test('bytesToBinary and binaryToBytes conversion round trip', () => {
        const originalBytes = [0, 127, 255]; // Example byte array
        const binaryString = bytesToBinary(originalBytes);
        const convertedBytes = binaryToBytes(binaryString);
        expect(convertedBytes).toEqual(originalBytes);
    });

    test('mnemonicToSeed throws error for invalid mnemonic', () => {
        const invalidMnemonic = 'invalid mnemonic string';
        expect(() => mnemonicToSeed(invalidMnemonic)).toThrow('Invalid mnemonic.');
    });

    test('generateEntropyBits throws error on invalid word count', () => {
        const invalidWordCounts = [11, 25];
        invalidWordCounts.forEach(count => {
            expect(() => generateEntropyBits(count)).toThrow('Invalid word count');
        });
    });

    test('generateMnemonic produces unique mnemonics', () => {
        const mnemonicSet = new Set();
        const iterations = 1000;
        for (let i = 0; i < iterations; i++) {
            mnemonicSet.add(generateMnemonic(12));
        }
        expect(mnemonicSet.size).toBe(iterations);
    });


    test('mnemonicToSeed generates consistent seed for same mnemonic and passphrase', () => {
        const mnemonic = generateMnemonic(12);
        const passphrase = 'test-passphrase';
        const seed1 = mnemonicToSeed(mnemonic, passphrase);
        const seed2 = mnemonicToSeed(mnemonic, passphrase);
        expect(seed1.equals(seed2)).toBe(true);
    });
});
