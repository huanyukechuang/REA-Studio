using System;
using System.IO;
using System.Text;

namespace ReaStudio.Services
{
    internal static class Log
    {
        private static readonly object Gate = new object();

        public static string LogDir
        {
            get
            {
                var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "REAStudio", "logs");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public static void Write(string message)
        {
            try
            {
                lock (Gate)
                {
                    var file = Path.Combine(LogDir, "app-" + DateTime.Now.ToString("yyyyMMdd") + ".log");
                    File.AppendAllText(file, DateTime.Now.ToString("HH:mm:ss.fff") + "  " + message + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch { }
        }
    }
}
