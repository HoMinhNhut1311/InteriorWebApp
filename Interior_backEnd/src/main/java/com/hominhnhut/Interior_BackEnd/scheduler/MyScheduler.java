package com.hominhnhut.WMN_BackEnd.scheduler;


import com.hominhnhut.WMN_BackEnd.utils.RanDomUtils;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;

@Component
public class MyScheduler {

    private final RanDomUtils ranDomUtils;

    public MyScheduler(RanDomUtils ranDomUtils) {
        this.ranDomUtils = ranDomUtils;
    }

    @Scheduled(cron = "0 */5 * * * *") // Chạy sau mỗi 5 phút
    public void executeTask() {
        ranDomUtils.getRandomCodes().forEach((rdc) -> {
            if (new Date().after(rdc.getDate())) {
                ranDomUtils.deleteRandomCode(rdc);
            }
        });
        System.out.println(ranDomUtils.getRandomCodes());
    }
}

