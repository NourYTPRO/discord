require('dotenv').config();
const { REST, Routes } = require('discord.js');

const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
const clientId = process.env.CLIENT_ID;
const guildId = process.env.GUILD_ID;
const mode = String(process.argv[2] || 'all').toLowerCase();

(async () => {
    try {
        if (!process.env.DISCORD_TOKEN || !clientId) {
            throw new Error('Missing DISCORD_TOKEN or CLIENT_ID in .env');
        }

        if ((mode === 'all' || mode === 'global')) {
            console.log('Started clearing global commands...');
            await rest.put(
                Routes.applicationCommands(clientId),
                { body: [] },
            );
            console.log('Successfully deleted all global commands.');
        }

        if (mode === 'all' || mode === 'guild') {
            if (!guildId) {
                console.log('GUILD_ID not set; skipped guild command clear.');
            } else {
                console.log(`Started clearing guild commands for ${guildId}...`);
                await rest.put(
                    Routes.applicationGuildCommands(clientId, guildId),
                    { body: [] },
                );
                console.log('Successfully deleted guild commands.');
            }
        }

        console.log('Done. Run deploy-commands.js to register commands again.');
    } catch (error) {
        console.error(error);
    }
})();
