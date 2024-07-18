package com.hominhnhut.WMN_BackEnd.domain.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MailRequest {
    String from;
    String to;
    String[] cc;
    String[] bcc;
    String subject;
    String body;
    String[] attachments;
    public MailRequest(String to, String subject, String body) {
        this.from = "hungvvvvv@gmail.com";
        this.to = to;
        this.subject = subject;
        this.body = body;
    }
}
