const paypal = require("paypal-rest-sdk");

paypal.configure({
  mode: "sandbox",
  client_id: "AUHh1j00UstZqQZ5ZiiS2lxCCqzt3X05C5DajR0dHBjpx2QcV2F8qUmSqQ9pHS6ZAcfnNCWnIZeYpi69",
  client_secret: "ED8Z1tOghybcAvgRe7wmvRj1Y7cR4BBvNI3y8nx4Plh1BP19IiX_bqxS3itjFRkXHsD1679ke_7t-D-4",
});

module.exports = paypal;
