require('dotenv').config()
const aws = require('aws-sdk');
const crypto = require('crypto');

const kms = new aws.KMS({
  accessKeyId: process.env.AWS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: 'us-east-1',
});
const params = {
  KeyId: process.env.KMS_KEY_ID, // CMK keyId
  KeySpec: 'AES_256', // Specifies the type of data key to return.
};

const iv = new Buffer('00000000000000000000000000000000', 'hex');
const algorithm = 'aes-256-cbc';

const encrypt = (key, data) => {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedData = cipher.update(data);
  encryptedData = Buffer.concat([encryptedData, cipher.final()]);
  return encryptedData.toString('hex');
};

const decrypt = (key, encryptedText) => {
  const decipher = crypto.createDecipheriv(algorithm, key, iv);

  const encryptedBuffer = Buffer.from(encryptedText, 'hex');
  let decryptedData = decipher.update(encryptedBuffer);
  decryptedData = Buffer.concat([decryptedData, decipher.final()]);
  return decryptedData.toString();
};

const generateDataKey = () => {
  return new Promise((resolve, reject) => {
    kms.generateDataKey(params, (err, generatedDataKey) => {
      if (err) {
        console.log(err);
        reject(err);
      } else {
        resolve(generatedDataKey);
      }
    });
  });
};

const decryptEncryptedDataKey = (encryptedDataKey) => {
  return new Promise((resolve, reject) => {
    const decryptParams = {
      CiphertextBlob: encryptedDataKey,
    };
    kms.decrypt(decryptParams, (err, decryptedDataKey) => {
      if (err) reject(err);
      else {
        resolve(decryptedDataKey);
      }
    });
  });
};

const main = async () => {
  const data = 'I am unencrypted, encrypt me!';

  console.log('--------------------------------------------------------');
  console.log('data: ', data);

  console.log('--------------------------------------------------------');
  const dataKeys = await generateDataKey();
  console.log('dataKeys: \n', dataKeys);

  console.log('--------------------------------------------------------');
  const encryptedData = encrypt(dataKeys.Plaintext, data);
  console.log('encrypted data: ', encryptedData);

  console.log('--------------------------------------------------------');
  const decryptedDataKey = await decryptEncryptedDataKey(dataKeys.CiphertextBlob);
  console.log('decryptedDataKey: \n', decryptedDataKey);

  console.log('--------------------------------------------------------');
  const decryptedData = decrypt(decryptedDataKey.Plaintext, encryptedData);
  console.log('decrypted data: ', decryptedData);
  console.log('--------------------------------------------------------');
};

main();