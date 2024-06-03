// Copyright (C) 2023 Haderech Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { HexString } from '@pinot/util/types';
import type { Registry, Signer, SignerPayloadRaw, SignerResult } from '@polkadot/types/types';

import { p256 } from '@noble/curves/p256';
import { compactAddLength, hexToU8a, u8aCmp, u8aConcat } from '@pinot/util';
import { blake2AsU8a, sha256AsU8a } from '@polkadot/util-crypto';

let id = 0;

type BinaryLike = Uint8Array | HexString | string;

export class WebAuthnSigner implements Signer {
  readonly #registry: Registry;
  readonly #credentialId: Uint8Array;
  readonly address: string;
  readonly addressRaw: Uint8Array;
  rpId?: string;

  constructor (registry: Registry, credentialId: BinaryLike, accountId: BinaryLike) {
    this.#registry = registry;
    this.#credentialId = this.#registry.createType('Binary', credentialId).toU8a(true);

    const parsedAccountId = this.#registry.createType('AccountId', accountId);

    this.address = parsedAccountId.toHuman() as string;
    this.addressRaw = parsedAccountId.toU8a();
  }

  public async signRaw ({ address, data }: SignerPayloadRaw): Promise<SignerResult> {
    if (this.address && this.address !== address) {
      throw new Error('Signer address does not match');
    }

    if (!navigator || !navigator.credentials) {
      throw new Error('WebAuthn is not supported in this environment');
    }

    const rpId = this.rpId;

    const response = ((await navigator.credentials.get({
      publicKey: {
        allowCredentials: [{
          id: this.#credentialId,
          type: 'public-key'
        }],
        challenge: blake2AsU8a(hexToU8a(data)),
        ...(rpId && { rpId })
      }
    })) as PublicKeyCredential).response as AuthenticatorAssertionResponse;

    const authenticatorData = new Uint8Array(response.authenticatorData);
    const clientDataJSON = new Uint8Array(response.clientDataJSON);
    const signedMessage = sha256AsU8a(u8aConcat(authenticatorData, sha256AsU8a(clientDataJSON)));
    const signature = p256.Signature.fromDER(new Uint8Array(response.signature)).normalizeS();
    const recoveryId = (() => {
      for (let i = 0; i < 4; i++){
        const recoveredSignature = signature.addRecoveryBit(i);
        const publicKey = recoveredSignature.recoverPublicKey(signedMessage).toRawBytes();
        const address = blake2AsU8a(publicKey);
        if (u8aCmp(address, this.addressRaw) === 0) {
          return i;
        }
      }
      throw new Error('Unable to find valid recovery id');
    })();

    return {
      id: ++id,
      signature: this.#registry.createType('ExtrinsicSignature', {
        /* eslint-disable sort-keys */
        WebAuthn: {
          clientDataJSON: compactAddLength(clientDataJSON),
          authenticatorData: compactAddLength(authenticatorData),
          signature: u8aConcat(compactAddLength(signature.toCompactRawBytes()), Uint8Array.from([recoveryId]))
        }
        /* eslint-enable sort-keys */
      }).toHex()
    };
  }

  public toString (): string {
    return this.address;
  }
}
