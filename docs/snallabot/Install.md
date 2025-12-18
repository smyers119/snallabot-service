# Notes for deploying snallabot yourself

This contain's information about deploying your own bot. This document assumes you have a basic understanding of the discord development portal and firebase console. 

## Discord bot settings

### General Information settings

Interactions endpoint URL:
```
https://YOUR_HOST/discord/webhook/slashCommand
```

### Installation settings

Your can uncheck User Install. 

For Guild Install settings add BOT scope and Administrator permission for testing.

### Oauth settings

Add redirect URL:
```
https://YOUR_HOST/dashboard/guilds
```

### Bot permissions

Enable all 3 intents:

Presence Intent, Server Members Intent, Message Content Intent

### Installing slash commands

This can be down from any terminal that supports curl

Install Global:
``` 
curl -X POST  YOUR_HOST/discord/webhook/commandsHandler --data '{"mode": "INSTALL"}' -H "Content-Type: application/json"
```
Install for a single guild

```
curl -X POST  YOUR_HOST/discord/webhook/commandsHandler --data '{"mode": "INSTALL", "guildId": "GUILD"}' -H "Content-Type: application/json"
```

## Firebase database settings

The following indexs need to be manually added:

| Collector ID    | Fields Indexed                             | Query Scope |
| --------------- | ------------------------------------------ | ----------- |
| MADDEN_SCHEDULE | stageIndex :arrow_up:  weekIndex :arrow_up:  seasonIndex :arrow_down: \__name__ :arrow_down: <br>  | Collection  |
| MADDEN_SCHEDULE | seasonIndex :arrow_up: stageIndex :arrow_up: weekIndex :arrow_up: timestamp :arrow_down: \__name__ :arrow_down: | Collection  |
| MADDEN_SCHEDULE | stageIndex :arrow_up: weekIndex :arrow_up: timestamp :arrow_down: \__name__ :arrow_down: | Collection  |