package com.hominhnhut.WMN_BackEnd.service.Interface;


import org.springframework.stereotype.Service;

public interface MyGmailService {

    void sendEmail(String recipient, String body, String subject);


}
