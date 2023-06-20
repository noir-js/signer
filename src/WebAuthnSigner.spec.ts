import { describe, expect, it } from 'vitest';
import { WebAuthnSigner } from './WebAuthnSigner.js'
import { TypeRegistry, Binary, UniversalAddress } from '@pinot/types';
import { u8aToHex } from '@pinot/util';

describe('WebAuthnSigner', (): void => {
  describe('construct', (): void => {
    it('can construct', (): void => {
      const registry = new TypeRegistry();
      registry.register({
        'AccountId': 'UniversalAddress',
        Binary,
        UniversalAddress,
      });

      const credentialId = 'vlinaQqUA5Elff-7mKulzg';
      const publicKey = 'ugCQDyDOUCZ4w6uVaQ6cjDapARUknVRX-09qqYiyYMEC09i8';

      const signer = new WebAuthnSigner(registry, credentialId, publicKey);
      expect(signer.address).toEqual(publicKey);
      expect(u8aToHex(signer.addressRaw)).toEqual('0x802403c83394099e30eae55a43a7230daa404549275515fed3daaa622c983040b4f62f');
    });
  });
});
