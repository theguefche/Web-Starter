package com.starter.backend.service;

import org.springframework.stereotype.Service;

@Service
public class ExceptionService {
    String packageName = "com.starter.backend"; // Replace with your package name

    public String retreiveDebugTrace(StackTraceElement[] stackTrace) {
        String debugTrace = "";

        for (int i = 0; i < stackTrace.length; i++) {
            StackTraceElement element = stackTrace[i];
            if (element.getClassName().startsWith(packageName)) {
                debugTrace += stackTrace[i - 1].toString() + " | ";
                debugTrace += element.toString();
                break;
            }
        }

        return debugTrace;
    }

}
