package com.hominhnhut.WMN_BackEnd.service.Interface;

import com.hominhnhut.WMN_BackEnd.domain.request.MailRequest;
import jakarta.mail.MessagingException;

public interface MailService {
     void send(MailRequest mail) throws MessagingException;
     void send(String to, String subject, String body)
            throws MessagingException;
}
