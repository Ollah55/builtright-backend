import nodemailer from "nodemailer";

const sendEmail = async ({ to, subject, html, cc, bcc, attachments = [] }) => {
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

export default sendEmail;
