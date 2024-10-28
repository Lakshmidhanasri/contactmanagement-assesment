const Contact = require("../models/Contact");

exports.addContact = async (req, res) => {
  const { name, email, phone, address, timezone } = req.body;
  const contact = new Contact({ name, email, phone, address, timezone });
  await contact.save();
  res.status(201).json(contact);
};

exports.getContacts = async (req, res) => {
  const contacts = await Contact.find();
  res.json(contacts);
};
