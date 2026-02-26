// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '@mysten/sui/bcs';
import type { SuiGrpcClient } from '@mysten/sui/grpc';
import { toBase64 } from '@mysten/sui/utils';

import { InvalidObjectError } from '../client/errors.js';

/**
 * Retry a gRPC call with exponential backoff when the server returns RESOURCE_EXHAUSTED (429).
 */
export async function withGrpcRetry<T>(
	fn: () => PromiseLike<T>,
	maxAttempts = 5,
	baseDelayMs = 1000,
): Promise<T> {
	for (let attempt = 1; attempt <= maxAttempts; attempt++) {
		try {
			return await fn();
		} catch (error: unknown) {
			const isRateLimit =
				error instanceof Error &&
				'code' in error &&
				(error as { code: string }).code === 'RESOURCE_EXHAUSTED';

			if (!isRateLimit || attempt === maxAttempts) {
				throw error;
			}

			const delay = baseDelayMs * Math.pow(2, attempt - 1);
			await new Promise((resolve) => setTimeout(resolve, delay));
		}
	}

	// Unreachable, but satisfies TypeScript.
	throw new Error('withGrpcRetry: exhausted attempts');
}

export type GrpcDynamicFieldInfo = {
	id: string;
	name: { type: string; value: Uint8Array | undefined };
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

	if (!bytes) throw new InvalidObjectError('gRPC response missing BCS data');

	const parsedObject = bcs.Object.parse(bytes);

	if (!parsedObject.data.Move) throw new InvalidObjectError('Error');

	const contents: Uint8Array = parsedObject.data.Move.contents;

	if (!contents) throw new InvalidObjectError('BCS Object missing MoveObject contents');

	return toBase64(contents);
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
	let pageToken: Uint8Array | undefined = undefined;

	// eslint-disable-next-line no-constant-condition
	while (true) {
		// eslint-disable-next-line no-loop-func
		const { response } = await withGrpcRetry(() =>
			client.stateService.listDynamicFields({
				parent: parentId,
				pageToken,
				readMask: { paths: ['field_id', 'name'] },
			}),
		);

		all.push(
			...response.dynamicFields.map((df) => ({
				id: df.fieldId ?? '',
				name: { type: df.name?.name ?? '', value: df.name?.value },
				type: df.valueType ?? '',
			})),
		);

		if (!response.nextPageToken) {
			break;
		}

		pageToken = response.nextPageToken;
	}

	return all;
}
