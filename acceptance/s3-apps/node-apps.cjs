// What Misskey and PeerTube send to their object storage, with the AWS SDK for JavaScript
// version both pin (3.1161.0) and the parameters of their storage code:
//
// - Misskey (packages/backend/src/core/S3Service.ts, DriveService.ts): an S3Client with
//   `requestChecksumCalculation: 'WHEN_REQUIRED'`; every file through `Upload` of lib-storage
//   with 8 MiB parts, `CacheControl: 'max-age=31536000, immutable'`, a Content-Disposition
//   with the file name and `ACL: 'public-read'` (objectStorageSetPublicRead); the original,
//   `webpublic-` and `thumbnail-` variants; deletes with DeleteObject.
// - PeerTube (server/core/lib/object-storage/object-storage-helpers.ts): `Upload` with
//   `queueSize: 4`, `leavePartsOnError: true`, the part size of `max_upload_part` and the
//   ACL of `upload_acl.public` (`public-read`) or `upload_acl.private` (`private`);
//   `updatePrefixACL` (ListObjectsV2, then PutObjectAcl per object) when a video turns
//   private or public; CopyObject with `MetadataDirective: 'REPLACE'`; ranged GetObject;
//   HeadObject; `removePrefix` (ListObjectsV2, then DeleteObject per object).
//
// Usage: node node-apps.cjs <misskey|peertube> <sdk dir> <endpoint> <access key> <secret key>
//        <bucket> <work dir>
// Exits non-zero, with the reason, when a step fails.

'use strict';

const { createRequire } = require('node:module');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const [app, sdkDir, endpoint, accessKeyId, secretAccessKey, bucket, workDir] = process.argv.slice(2);
const sdk = createRequire(path.join(sdkDir, 'package.json'));
const s3 = sdk('@aws-sdk/client-s3');
const { Upload } = sdk('@aws-sdk/lib-storage');

const credentials = { accessKeyId, secretAccessKey };

function check(condition, message) {
	if (!condition) {
		throw new Error(message);
	}
}

/** The public URL of a key (path style). */
function publicUrl(key) {
	return `${endpoint}/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
}

/** An anonymous GET of a key: status, headers and body. */
async function anonymous(key) {
	const response = await fetch(publicUrl(key));
	const body = Buffer.from(await response.arrayBuffer());
	return { status: response.status, headers: response.headers, body };
}

/** A file of `size` random bytes in the work directory. */
function randomFile(name, size) {
	const file = path.join(workDir, name);
	fs.writeFileSync(file, crypto.randomBytes(size));
	return file;
}

async function misskey() {
	const client = new s3.S3Client({
		endpoint,
		credentials,
		region: 'us-east-1',
		forcePathStyle: true,
		requestChecksumCalculation: 'WHEN_REQUIRED',
		responseChecksumValidation: 'WHEN_REQUIRED',
	});
	const prefix = 'misskey';
	const upload = (params) => new Upload({ client, params, partSize: 8 * 1024 * 1024 }).done();
	const common = {
		Bucket: bucket,
		CacheControl: 'max-age=31536000, immutable',
		ACL: 'public-read',
	};
	const image = randomFile('photo.png', 300 * 1024);
	const video = randomFile('clip.mp4', 20 * 1024 * 1024);
	const files = [
		// The original, named by its UUID; a file name that needs RFC 5987 encoding.
		{ key: `${prefix}/${crypto.randomUUID()}.png`, file: image, type: 'image/png',
			disposition: "inline; filename=\"cat ?.png\"; filename*=UTF-8''cat%20%E2%80%A6.png" },
		{ key: `${prefix}/webpublic-${crypto.randomUUID()}.webp`, file: image, type: 'image/webp',
			disposition: 'inline; filename="photo.webp"' },
		{ key: `${prefix}/thumbnail-${crypto.randomUUID()}.webp`, file: image, type: 'image/webp',
			disposition: 'inline; filename="photo.png.thumbnail.webp"' },
		// Larger than a part: a multipart upload that carries the ACL from its creation.
		{ key: `${prefix}/${crypto.randomUUID()}.mp4`, file: video, type: 'video/mp4',
			disposition: 'inline; filename="clip.mp4"' },
	];
	for (const { key, file, type, disposition } of files) {
		await upload({
			...common,
			Key: key,
			Body: fs.createReadStream(file),
			ContentType: type,
			ContentDisposition: disposition,
		});
		const got = await anonymous(key);
		check(got.status === 200, `anonymous GET ${key}: ${got.status}`);
		check(got.body.equals(fs.readFileSync(file)), `${key}: other content`);
		check(got.headers.get('content-type') === type, `${key}: ${got.headers.get('content-type')}`);
		check(got.headers.get('cache-control') === common.CacheControl, `${key}: cache-control`);
		check(got.headers.get('content-disposition') === disposition,
			`${key}: content-disposition ${got.headers.get('content-disposition')}`);
		check(got.headers.get('x-content-type-options') === 'nosniff', `${key}: nosniff`);
	}
	for (const { key } of files) {
		await client.send(new s3.DeleteObjectCommand({ Bucket: bucket, Key: key }));
		const gone = await anonymous(key);
		check(gone.status === 403, `deleted ${key}: ${gone.status}`);
	}
}

async function peertube() {
	// PeerTube keeps the SDK's default checksums (CRC32 in trailers).
	const client = new s3.S3Client({ endpoint, credentials, region: 'us-east-1', forcePathStyle: true });
	const uuid = crypto.randomUUID();
	const prefix = `streaming-playlists/hls/${uuid}/`;
	const upload = (key, file, contentType, acl, partSize) => {
		const input = { Bucket: bucket, Key: key, Body: fs.createReadStream(file), ContentType: contentType };
		if (acl) {
			input.ACL = acl;
		}
		return new Upload({ client, queueSize: 4, partSize, params: input, leavePartsOnError: true }).done();
	};
	const playlist = path.join(workDir, 'master.m3u8');
	fs.writeFileSync(playlist, '#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=800000\n720.m3u8\n');
	const fragmented = randomFile('720-fragmented.mp4', 12 * 1024 * 1024);
	const keys = [`${prefix}master.m3u8`, `${prefix}${uuid}-720-fragmented.mp4`];
	// max_upload_part: 100 MB by default (one request), 5 MiB for the multipart path.
	await upload(keys[0], playlist, 'application/x-mpegURL', 'public-read', 100 * 1024 * 1024);
	await upload(keys[1], fragmented, 'video/mp4', 'public-read', 5 * 1024 * 1024);
	for (const key of keys) {
		check((await anonymous(key)).status === 200, `public ${key}`);
	}

	// Ranged reads (PeerTube proxies private files and serves byte ranges).
	const ranged = await client.send(new s3.GetObjectCommand({ Bucket: bucket, Key: keys[1], Range: 'bytes=100-199' }));
	const part = Buffer.from(await ranged.Body.transformToByteArray());
	check(part.equals(fs.readFileSync(fragmented).subarray(100, 200)), 'ranged read');
	const head = await client.send(new s3.HeadObjectCommand({ Bucket: bucket, Key: keys[1] }));
	check(head.ContentLength === 12 * 1024 * 1024, `HeadObject size ${head.ContentLength}`);

	// The video turns private: every object of its prefix gets the private ACL, and back.
	const applyOnPrefix = async (command) => {
		const listed = await client.send(new s3.ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }));
		const objects = listed.Contents ?? [];
		await Promise.all(objects.map((object) => client.send(command(object.Key))));
		return objects.length;
	};
	const setAcl = (acl) => applyOnPrefix((key) => new s3.PutObjectAclCommand({ Bucket: bucket, Key: key, ACL: acl }));
	check((await setAcl('private')) === 2, 'listed both objects');
	for (const key of keys) {
		check((await anonymous(key)).status === 403, `private ${key}`);
	}
	await setAcl('public-read');
	for (const key of keys) {
		check((await anonymous(key)).status === 200, `public again ${key}`);
	}

	// A copy with new metadata, as when a file moves to another storage prefix.
	const copied = `${prefix}copy-${uuid}.mp4`;
	await client.send(new s3.CopyObjectCommand({
		Bucket: bucket,
		Key: copied,
		CopySource: `${bucket}/${keys[1]}`,
		MetadataDirective: 'REPLACE',
		ContentType: 'video/mp4',
		ACL: 'public-read',
	}));
	const copy = await anonymous(copied);
	check(copy.status === 200 && copy.body.equals(fs.readFileSync(fragmented)), 'copy');

	// removePrefix: one DeleteObject per listed object.
	check((await applyOnPrefix((key) => new s3.DeleteObjectCommand({ Bucket: bucket, Key: key }))) === 3, 'removed three');
	const left = await client.send(new s3.ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }));
	check((left.KeyCount ?? 0) === 0, `objects left: ${left.KeyCount}`);
}

const scenarios = { misskey, peertube };
scenarios[app]().catch((err) => {
	console.error(`${app}: ${err.stack ?? err}`);
	process.exit(1);
});
