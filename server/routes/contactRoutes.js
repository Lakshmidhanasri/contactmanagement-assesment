const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const {
  addContact,
  getContacts,
  updateContact,
  deleteContact,
  batchProcessContacts,
} = require("../controllers/contactController");
const { body } = require("express-validator");

const router = express.Router();

router.use(authMiddleware); // This should be a valid middleware function

router.post(
  "/contacts",
  body("name").notEmpty().withMessage("Name is required"),
  body("email").isEmail().withMessage("Invalid email"),
  body("phone").notEmpty().withMessage("Phone number is required"),
  body("address").notEmpty().withMessage("Address is required"),
  body("timezone").notEmpty().withMessage("Timezone is required"),
  addContact
);

router.get("/contacts", getContacts);
router.put("/contacts/:contactId", updateContact);
router.delete("/contacts/:contactId", deleteContact);
router.post("/contacts/batch", batchProcessContacts);

module.exports = router;
