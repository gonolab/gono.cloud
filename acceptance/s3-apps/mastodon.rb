# What Mastodon sends to its object storage, with the aws-sdk gem versions it locks
# (aws-sdk-s3 1.242.0, aws-sdk-core 3.268.0) and the options of
# config/initializers/paperclip.rb with S3_ENDPOINT set: path style, signature v4, no
# retries, 5 s timeouts; uploads through
# Paperclip's `upload_file` with the `public-read` ACL (S3_PERMISSION), its Cache-Control and
# a 15 MB multipart threshold; downloads in one request without checksum mode (Mastodon's
# S3Extensions); `acl.put` to make the media of a suspended account private and public again;
# and the batch deletes of AttachmentBatch (DeleteObjects, up to 1000 keys).
#
# Usage: ruby mastodon.rb <endpoint> <access key> <secret key> <bucket> <work dir>
# Exits non-zero, with the reason, when a step fails.

# The versions of Mastodon's Gemfile.lock.
gem 'aws-eventstream', '1.4.1'
gem 'aws-partitions', '1.1305.0'
gem 'aws-sigv4', '1.12.1'
gem 'aws-sdk-core', '3.268.0'
gem 'aws-sdk-kms', '1.143.0'
gem 'aws-sdk-s3', '1.242.0'
require 'aws-sdk-s3'
require 'net/http'
require 'securerandom'
require 'digest'

endpoint, access_key, secret_key, bucket_name, work_dir = ARGV

def check(condition, message)
  raise message unless condition
end

client = Aws::S3::Client.new(
  endpoint: endpoint,
  region: 'us-east-1',
  force_path_style: true,
  credentials: Aws::Credentials.new(access_key, secret_key),
  signature_version: 'v4',
  http_open_timeout: 5,
  http_read_timeout: 5,
  http_idle_timeout: 5,
  retry_limit: 0
)
bucket = Aws::S3::Resource.new(client: client).bucket(bucket_name)

def anonymous(endpoint, bucket, key)
  Net::HTTP.get_response(URI("#{endpoint}/#{bucket}/#{key}"))
end

cache_control = 'public, max-age=315576000, immutable'
id = SecureRandom.random_number(10**18).to_s.rjust(18, '0')
id_path = id.scan(/\d{3}/).join('/')
uploads = {
  "media_attachments/files/#{id_path}/original/#{SecureRandom.hex(8)}.png" =>
    ['image/png', 400 * 1024],
  "media_attachments/files/#{id_path}/small/#{SecureRandom.hex(8)}.png" =>
    ['image/png', 40 * 1024],
  # Above S3_MULTIPART_THRESHOLD (15 MB): upload_file sends it in parts.
  "media_attachments/files/#{id_path}/original/#{SecureRandom.hex(8)}.mp4" =>
    ['video/mp4', 20 * 1024 * 1024],
  "accounts/avatars/#{id_path}/original/#{SecureRandom.hex(8)}.jpg" =>
    ['image/jpeg', 100 * 1024]
}

uploads.each do |key, (content_type, size)|
  path = File.join(work_dir, File.basename(key))
  File.binwrite(path, SecureRandom.random_bytes(size))
  object = bucket.object(key)
  check(object.upload_file(path, acl: 'public-read', content_type: content_type,
                                 cache_control: cache_control,
                                 multipart_threshold: 15 * 1024 * 1024),
        "upload_file #{key}")
  response = anonymous(endpoint, bucket_name, key)
  check(response.code == '200', "anonymous GET #{key}: #{response.code}")
  check(response.body.b == File.binread(path), "#{key}: other content")
  check(response['content-type'] == content_type, "#{key}: #{response['content-type']}")
  check(response['cache-control'] == cache_control, "#{key}: cache-control")

  # Reprocessing downloads the file in one request, without checksum mode.
  copy = "#{path}.download"
  object.download_file(copy, mode: 'single_request', checksum_mode: 'DISABLED')
  check(Digest::SHA256.file(copy) == Digest::SHA256.file(path), "#{key}: download")
end

# Suspending an account makes its media private; unsuspending public again.
keys = uploads.keys
keys.each { |key| bucket.object(key).acl.put(acl: 'private') }
keys.each do |key|
  code = anonymous(endpoint, bucket_name, key).code
  check(code == '403', "private #{key}: #{code}")
end
keys.each { |key| bucket.object(key).acl.put(acl: 'public-read') }
keys.each do |key|
  code = anonymous(endpoint, bucket_name, key).code
  check(code == '200', "public again #{key}: #{code}")
end

# AttachmentBatch deletes in batches of up to 1000 keys.
result = bucket.delete_objects(delete: { objects: keys.map { |key| { key: key } }, quiet: true })
check(result.errors.empty?, "delete_objects: #{result.errors.inspect}")
keys.each do |key|
  code = anonymous(endpoint, bucket_name, key).code
  check(code == '403', "deleted #{key}: #{code}")
end
puts 'mastodon: ok'
