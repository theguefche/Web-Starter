package com.starter.backend.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.starter.backend.security.TokenProvider;

@Component
public class CacheEvictor {

    @Autowired
    private CacheManager cacheManager;

    @Autowired
    private TokenProvider service;

    @Scheduled(fixedRate = 60000 ) // run every 60 seconds
    public void evictCacheAtIntervals() {
        // in this methode we will remove all expired token from invalidTokens in

        Cache invalidTokensCache = cacheManager.getCache("invalidTokens");
        ConcurrentMapCache cache = (ConcurrentMapCache) invalidTokensCache;
    
        if (cache.getNativeCache() != null) {
            cache.getNativeCache().entrySet().forEach(r -> {
                if (service.isTokenExpiredV2(r.getKey().toString())) {
                    invalidTokensCache.evict(r.getKey());
                } else {
                    System.out.println(r.getKey());
                }
            });
        }

    }

}
