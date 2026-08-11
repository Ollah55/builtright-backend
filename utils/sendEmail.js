import nodemailer from "nodemailer";
import axios from "axios";

const asRecipients = (recipients) => {
  if (!recipients) return undefined;
  return Array.isArray(recipients) ? recipients : [recipients];
};

const resendAttachments = (attachments) => attachments.map((attachment) => ({
  filename: attachment.filename,
  content: Buffer.isBuffer(attachment.content)
    ? attachment.content.toString("base64")
    : attachment.content,
  content_type: attachment.contentType,
}));

const sendWithResend = async ({ to, subject, html, cc, bcc, attachments }) => {
  const response = await axios.post(
    "https://api.resend.com/emails",
    {
      from: process.env.RESEND_FROM || "BuiltRight Services <notifications@builtrightltd.com>",
      to: asRecipients(to),
      cc: asRecipients(cc),
      bcc: asRecipients(bcc),
      subject,
      html,
      attachments: resendAttachments(attachments),
    },
    {
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      timeout: 30000,
    },
  );

  return response.data;
};

const sendWithSmtp = async ({ to, subject, html, cc, bcc, attachments }) => {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
    family: 4,
    connectionTimeout: 30000,
    greetingTimeout: 30000,
    socketTimeout: 30000,
  });

  await transporter.verify();

  const info = await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    cc,
    bcc,
    subject,
    html,
    attachments,
  });

  return info;
};

const sendEmail = async (message) => {
  if (process.env.RESEND_API_KEY) {
    return sendWithResend(message);
  }

  return sendWithSmtp(message);
};

export default sendEmail;
