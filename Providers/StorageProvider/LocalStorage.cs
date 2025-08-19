
namespace AuthCenter.Providers.StorageProvider
{
    public class LocalStorage(string prefix, string baseDir) : IStorageProvider
    {
        private readonly string _prefix = prefix;
        private readonly string _baseDir = baseDir;

        public async Task<StorageFileInfo> AddFile(Stream fileStream, string filename, string extension)
        {
            if (!extension.All(char.IsLetterOrDigit))
            {
                throw new Exception("扩展名错误");
            }

            string newFilename = $"{Guid.NewGuid():N}-{DateTimeOffset.Now.ToUnixTimeMilliseconds()}.{extension}";
            string storagePath = Path.Combine(Path.Combine(_baseDir, _prefix), newFilename);

            if (!Directory.Exists(_prefix))
            {
                Directory.CreateDirectory(_prefix);
            }

            using (var fs = File.Create(storagePath))
            {
                await fileStream.CopyToAsync(fs);
                fs.Flush();
            }

            return new StorageFileInfo { Name = filename, Path = Path.Combine("/api/static", _prefix, newFilename).Replace("\\", "/") };
        }

        public Task<bool> RemoveFile(string filename)
        {
            if (!filename.All(c => char.IsLetterOrDigit(c) || c == '-'))
            {
                return Task.FromResult(false);
            }
            string storagePath = Path.Join(_prefix, filename);

            if (!File.Exists(storagePath))
            {
                return Task.FromResult(false);
            }

            File.Delete(storagePath);
            return Task.FromResult(true);
        }
    }
}
