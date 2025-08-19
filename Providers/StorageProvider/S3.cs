using Amazon;
using Amazon.S3;
using Amazon.S3.Model;

namespace AuthCenter.Providers.StorageProvider
{
    public class S3(string accessKey, string accessSecret, string endpoint,string bucket, string region, string prefix) : IStorageProvider
    {
        private readonly string _accessKey = accessKey;
        private readonly string _accessKeySecret = accessSecret;
        private readonly string _prefix = prefix;
        private readonly string _bucket = bucket;

        private readonly AmazonS3Client client = new(accessKey, accessSecret, new AmazonS3Config
        {
            RegionEndpoint = RegionEndpoint.GetBySystemName(region),
            ServiceURL = endpoint,
            ForcePathStyle = true,
        });

        public async Task<StorageFileInfo> AddFile(Stream fileStream, string filename, string extension)
        {
            if (!extension.All(char.IsLetterOrDigit))
            {
                throw new Exception("扩展名错误");
            }

            string newFilename = $"{Guid.NewGuid():N}-{DateTimeOffset.Now.ToUnixTimeMilliseconds()}.{extension}";
            var request = new PutObjectRequest
            {
                BucketName = _bucket,
                Key = newFilename,
                FilePath = _prefix,
                InputStream = fileStream,
                CannedACL = S3CannedACL.PublicRead,
            };

            var resp = await client.PutObjectAsync(request);

            return new StorageFileInfo { Name = newFilename, Path = Path.Combine(_bucket, newFilename) };
        }


        public async Task<bool> RemoveFile(string filename)
        {
            var request = new DeleteObjectRequest
            {
                BucketName = _bucket,
                Key = filename
            };

            await client.DeleteObjectAsync(request);

            return true;
        }
    }
}
