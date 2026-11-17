using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace ReaStudio.Services
{
    /// <summary>样本 SHA-256 计算与内存缓存，避免报告多次重复哈希大文件。</summary>
    internal static class HashCache
    {
        private static readonly Dictionary<string, (long size, DateTime mtime, string hash)> Cache = new Dictionary<string, (long, DateTime, string)>(StringComparer.OrdinalIgnoreCase);

        public static string Get(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return "";
                var fi = new FileInfo(path);
                if (fi.Length > 512L * 1024 * 1024) return "（文件过大，已跳过哈希）";
                lock (Cache)
                {
                    if (Cache.TryGetValue(fi.FullName, out var c) && c.size == fi.Length && c.mtime == fi.LastWriteTimeUtc)
                        return c.hash;
                }
                using var fs = File.OpenRead(fi.FullName);
                using var sha = SHA256.Create();
                var hash = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
                lock (Cache) { Cache[fi.FullName] = (fi.Length, fi.LastWriteTimeUtc, hash); }
                return hash;
            }
            catch { return ""; }
        }
    }
}
