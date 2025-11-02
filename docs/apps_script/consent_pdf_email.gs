/**
 * Google Apps Script — attach to your Google Form (Extensions > Apps Script).
 * On form submit, generates a PDF receipt of responses and emails both parties.
 *
 * Setup:
 * 1) Open the Form > Extensions > Apps Script, paste this file.
 * 2) In Triggers, add: onFormSubmit → Event type: On form submit.
 * 3) Set SENDER_NAME, INTERNAL_EMAIL.
 */

const SENDER_NAME = 'Security Surface Check';
const INTERNAL_EMAIL = 'security@yourcompany.com'; // change me

function onFormSubmit(e) {
  const response = e.response || e.namedValues ? e : wrapEvent(e);
  const namedValues = response.namedValues; // { Question: [Answer] }

  const recipient = getPrimaryRecipient(namedValues) || INTERNAL_EMAIL;
  const pdfBlob = buildPdf(namedValues);
  const subject = 'Scope & Consent — Receipt';
  const body = 'Attached is the PDF copy of your scope and consent.\n\n— ' + SENDER_NAME;

  MailApp.sendEmail({
    to: recipient,
    cc: INTERNAL_EMAIL,
    name: SENDER_NAME,
    subject: subject,
    body: body,
    attachments: [pdfBlob]
  });
}

function wrapEvent(e) {
  // Convert older e format to consistent shape
  const resp = e.response || FormApp.getActiveForm().getResponses().pop();
  return { response: resp, namedValues: resp.getItemResponses().reduce((acc, ir) => {
    acc[ir.getItem().getTitle()] = [String(ir.getResponse())];
    return acc;
  }, {}) };
}

function getPrimaryRecipient(namedValues) {
  // Tries to find an email answer from common labels
  const keys = Object.keys(namedValues);
  const emailKey = keys.find(k => /work email|email address/i.test(k));
  if (emailKey) {
    const val = (namedValues[emailKey] || [])[0];
    if (val && /@/.test(val)) return val.trim();
  }
  return null;
}

function buildPdf(namedValues) {
  const rows = Object.keys(namedValues).map(k => ({ key: k, value: (namedValues[k]||[''])[0] }));
  const html = HtmlService.createTemplateFromFile('email_template').evaluate().getContent()
    .replace('%%DATE%%', new Date().toISOString())
    .replace('%%ROWS_JSON%%', JSON.stringify(rows));

  const blob = Utilities.newBlob(html, 'text/html', 'ScopeConsent.html').getAs('application/pdf');
  blob.setName('Scope_Consent_' + Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyyMMdd_HHmm') + '.pdf');
  return blob;
}

// Include file helper if needed in the future
function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}


