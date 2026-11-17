using System;
using System.IO;

namespace ReaStudio.Services
{
    internal static class WebViewEnvironment
    {
        public static string UserDataFolder
        {
            get
            {
                var dir = Path.Combine(Storage.AppRoot, "webview");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public static System.Threading.Tasks.Task CreateAsync() => System.Threading.Tasks.Task.CompletedTask;
    }
}
