package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.domain.request.MailRequest;
import com.hominhnhut.WMN_BackEnd.service.Interface.MailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
@Slf4j
public class MailServiceImpl implements MailService {
    JavaMailSender javaMailSender;
    @Override
    public void send(MailRequest mail) throws MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "utf-8");
        helper.setFrom(mail.getFrom());
        helper.setTo(mail.getTo());
        helper.setSubject(mail.getSubject());
        helper.setText(mail.getBody(), true);
        helper.setReplyTo(mail.getFrom());
        String[] cc = mail.getCc();
        if(cc != null && cc.length > 0) {

            helper.setCc(cc);
        }
        String[] bcc = mail.getBcc();
        if(bcc != null && bcc.length > 0) {
            helper.setBcc(bcc);
        }
        String[] attachments = mail.getAttachments();
        if(attachments != null && attachments.length > 0) {
            for(String path: attachments) {
                File file = new File(path);
                helper.addAttachment(file.getName(), file);
            }
        }
        javaMailSender.send(message);
    }

    @Override
    public void send(String to, String subject, String body) throws MessagingException {

    }
}
