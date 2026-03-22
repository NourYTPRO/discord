require('dotenv').config(); // Load variables from .env
const { REST, Routes } = require('discord.js');
const fs = require('node:fs');

const commands = [];
const commandFiles = fs.readdirSync('./commands').filter(file => file.endsWith('.js'));

for (const file of commandFiles) {
    const command = require(`./commands/${file}`);
    if ('data' in command && 'execute' in command) {
        const json = command.data.toJSON();
        commands.push(json);
    } else {
        console.log(`[WARNING] The command at ./commands/${file} is missing a required "data" or "execute" property.`);
    }
}

// Grab variables from process.env
const token = process.env.DISCORD_TOKEN;
const clientId = process.env.CLIENT_ID;
const guildId = process.env.GUILD_ID;

const rest = new REST({ version: '10' }).setToken(token);

(async () => {
    try {
        const globalCommands = commands.filter((cmd) => cmd.name !== 'add');
        console.log(`Started refreshing ${commands.length} application (/) commands.`);

        if (guildId) {
            await rest.put(
                Routes.applicationGuildCommands(clientId, guildId),
                { body: commands },
            );
            console.log('Successfully reloaded guild application (/) commands!');
        } else {
            console.log('GUILD_ID not set; skipped guild application (/) command reload.');
        }

        // Publish commands globally (exclude owner-only commands like /add).
        await rest.put(
            Routes.applicationCommands(clientId),
            { body: globalCommands },
        );

        console.log(`Successfully reloaded ${globalCommands.length} global application (/) command(s)!`);
    } catch (error) {
        console.error(error);
    }
})();
