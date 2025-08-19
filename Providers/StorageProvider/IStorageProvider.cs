using AuthCenter.Models;

namespace AuthCenter.Providers.StorageProvider
{
    public class StorageFileInfo
    {
        public required string Name { get; set; }
        public required string Path { get; set; }
    }
    public interface IStorageProvider
    {
        public Task<StorageFileInfo> AddFile(Stream fileStream, string filename, string extension);
        public Task<bool> RemoveFile(string filename);

        public static IStorageProvider GetStorageProvider(Provider provider, string baseDir) {
            if (provider.SubType == "Local")
            {
                return new LocalStorage(provider.Body ?? "", baseDir);
            } else
            {
                return new S3(provider.ClientId!, provider.ClientSecret!, provider.ConfigureUrl!, provider.Subject!, provider.RegionId!, provider.Body!);
            }

            throw new NotImplementedException();
        }
    }
}
