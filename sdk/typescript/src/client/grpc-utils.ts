// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { SuiGrpcClient } from '@mysten/sui/grpc';
import { toBase64 } from '@mysten/sui/utils';

import { InvalidObjectError } from './errors.js';

export type GrpcDynamicFieldInfo = {
	id: string;
	name: { type: string; bcs: Uint8Array | undefined };
	type: string;
};

/**
 * Extract BCS bytes as a base64 string from a gRPC getObject response.
 *
 * @param obj - The response from ledgerService.getObject()
 * @returns Base64-encoded BCS bytes
 * @throws {InvalidObjectError} If the response does not contain BCS data
 */
export function grpcObjToBcs(obj: {
	response: { object?: { bcs?: { value?: Uint8Array } } | null };
}): string {
	const bytes = obj.response.object?.bcs?.value;
	if (!bytes) {
		throw new InvalidObjectError('gRPC response missing BCS data');
	}
	return toBase64(bytes);
}

/**
 * Fetch all dynamic fields for a parent object, handling pagination automatically.
 *
 * @param client - The SuiGrpcClient instance
 * @param parentId - The object ID of the parent
 * @returns Array of all dynamic field entries
 */
export async function grpcFetchAllDynamicFields(
	client: SuiGrpcClient,
	parentId: string,
): Promise<GrpcDynamicFieldInfo[]> {
	const all: GrpcDynamicFieldInfo[] = [];
	let cursor: string | null = null;

	// eslint-disable-next-line no-constant-condition
	while (true) {
		const response = await client.core.getDynamicFields({
			parentId,
			cursor,
		});

		all.push(...response.dynamicFields);

		if (!response.hasNextPage || response.cursor === cursor) {
			break;
		}

		cursor = response.cursor;
	}

	return all;
}
