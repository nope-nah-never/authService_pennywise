package com.pennywise.authService.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class EmailFormat {

    private String recipient;
    private String msgBody;
    private String subject;
    //private String attachment;

    public String getSubject() {
        return subject;
    }

    public String getMsgBody() {
        return msgBody;
    }

    public String getRecipient() {
        return recipient;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setMsgBody(String msgBody) {
        this.msgBody = msgBody;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }
}
