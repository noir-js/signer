import { describe, expect, it } from 'vitest';
import { WebAuthnSigner } from './WebAuthnSigner.js'
import { TypeRegistry, Binary } from '@pinot/types';
import { decodeAddress, u8aToHex } from '@pinot/util';

describe('WebAuthnSigner', (): void => {
  describe('construct', (): void => {
    it('can construct', (): void => {
      const registry = new TypeRegistry();
      registry.register({
        Binary,
      });

      const credentialId = 'vlinaQqUA5Elff-7mKulzg';
      const accountId = '5HGeP4pgVYAGof7ZUVLmAurkRRFSLZQ5JSB49FMAEKWUUTbF';

      const signer = new WebAuthnSigner(registry, credentialId, accountId);
      expect(signer.address).toEqual(accountId);
      expect(u8aToHex(signer.addressRaw)).toEqual('0xe6486944aec720fb45fc1fd69444107128f516a7ebb7fd279f5f25dc4c1f5d14');
    });
  });
});
