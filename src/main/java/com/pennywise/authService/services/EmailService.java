package com.pennywise.authService.services;


import com.pennywise.authService.dtos.EmailFormat;

public interface EmailService{

    // To send a simple email
    String sendSimpleMail(EmailFormat details);
    // To send an email with attachment
    //String sendMailWithAttachment(EmailFormat details);
}
