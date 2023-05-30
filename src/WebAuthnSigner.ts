// Copyright (C) 2023 Haderech Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { HexString } from '@pinot/util/types';
import type { Registry, Signer, SignerPayloadRaw, SignerResult } from '@polkadot/types/types';

import { compactAddLength, hexToU8a } from '@pinot/util';
import { blake2AsU8a } from '@polkadot/util-crypto';

let id = 0;

type BinaryLike = Uint8Array | HexString | string;

export class WebAuthnSigner implements Signer {
  readonly #registry: Registry;
  readonly #credentialId: Uint8Array;
  readonly address: string;
  readonly addressRaw: Uint8Array;

  constructor (registry: Registry, credentialId: BinaryLike, publicKey: BinaryLike) {
    this.#registry = registry;
    this.#credentialId = this.#registry.createType('Binary', credentialId).toU8a(true);

    const accountId = this.#registry.createType('AccountId', publicKey);

    this.address = accountId.toHuman() as string;
    this.addressRaw = accountId.toU8a();
  }

  public async signRaw ({ address, data }: SignerPayloadRaw): Promise<SignerResult> {
    if (this.address && this.address !== address) {
      throw new Error('Signer address does not match');
    }

    if (!navigator || !navigator.credentials) {
      throw new Error('WebAuthn is not supported in this environment');
    }

    const response = ((await navigator.credentials.get({
      publicKey: {
        allowCredentials: [{
          id: this.#credentialId,
          type: 'public-key'
        }],
        challenge: blake2AsU8a(hexToU8a(data))
      }
    })) as PublicKeyCredential).response as AuthenticatorAssertionResponse;

    return {
      id: ++id,
      signature: this.#registry.createType('ExtrinsicSignature', {
        /* eslint-disable sort-keys */
        WebAuthn: {
          clientDataJSON: compactAddLength(new Uint8Array(response.clientDataJSON)),
          authenticatorData: compactAddLength(new Uint8Array(response.authenticatorData)),
          signature: compactAddLength(new Uint8Array(response.signature))
        }
        /* eslint-enable sort-keys */
      }).toHex()
    };
  }

  public toString (): string {
    return this.address;
  }
}
