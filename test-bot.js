// test-bot.js
const { Client, GatewayIntentBits } = require('discord.js');

const BOT_TOKEN = process.env.BOT_TOKEN;

if (!BOT_TOKEN) {
  console.error("❌ BOT_TOKEN missing!");
  process.exit(1);
}

const bot = new Client({ intents: [GatewayIntentBits.Guilds] });

bot.once('ready', () => {
  console.log(`✅ Bot is online as ${bot.user.tag}`);
});

bot.login(BOT_TOKEN).catch(err => {
  console.error("❌ Failed to login:", err);
});
