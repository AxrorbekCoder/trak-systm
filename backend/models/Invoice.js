// models/Invoice.js
const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('track_system', 'root', '', {
  host: 'localhost',
  dialect: 'mysql',
});

const Invoice = sequelize.define('invoice', {
  tracking_code: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  status: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

module.exports = Invoice;
