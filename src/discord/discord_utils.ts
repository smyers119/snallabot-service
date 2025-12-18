import { ParameterizedContext } from "koa"
import { verifyKey } from "discord-interactions"
import { APIApplicationCommand, APIChannel, APIEmoji, APIGuild, APIGuildMember, APIMessage, APIThreadChannel, APIUser, ChannelType, InteractionResponseType, RESTPostAPIApplicationCommandsJSONBody } from "discord-api-types/v10"
import { CategoryId, ChannelId, DiscordIdType, MessageId, RoleId, UserId } from "./settings_db"
import { createDashboard } from "./commands/dashboard"
import { GameResult, MADDEN_SEASON, MaddenGame, Team, getMessageForWeek } from "../export/madden_league_types"
import MaddenDB, { TeamList } from "../db/madden_db"
import { LeagueLogos } from "../db/view"
import EventDB from "../db/events_db"
import { ConfirmedSimV2, SimResult } from "../db/events"

export enum CommandMode {
  INSTALL = "INSTALL",
  DELETE = "DELETE"
}

export type DiscordError = { message: string, code: number, retry_after?: number, errors?: { name: { _errors: { code: string, message: string }[] } } }

// https://discord.com/developers/docs/topics/opcodes-and-status-codes
export class DiscordRequestError extends Error {
  code: number
  originalError: DiscordError
  constructor(error: DiscordError) {
    super(JSON.stringify(error))
    this.name = "DiscordError"
    this.code = error.code
    this.originalError = error
  }

  isPermissionError() {
    return this.code == 50013 || this.code == 50001
  }
}

export class NoConnectedLeagueError extends Error {
  constructor(guild_id: string) {
    super(`There is no Madden league connected to this Discord server. To connect, setup the dashboard at this url: ${createDashboard(guild_id)}`)
  }
}

const UNKNOWN_MESSAGE = 10008
const UNKNOWN_CHANNEL = 10003

export class SnallabotDiscordError extends Error {
  guidance: string
  code: number
  constructor(error: DiscordRequestError, guidance: string) {
    super(error.message)
    this.name = "SnallabotDiscordError"
    this.guidance = guidance
    this.code = error.code
  }

  isDeletedChannel() {
    return this.code === UNKNOWN_CHANNEL
  }

  isDeletedMessage() {
    return this.code === UNKNOWN_MESSAGE
  }
}

export interface DiscordClient {
  interactionVerifier(ctx: ParameterizedContext): Promise<boolean>,
  handleSlashCommand(mode: CommandMode, command: RESTPostAPIApplicationCommandsJSONBody, guild?: string): Promise<void>,
  editOriginalInteraction(token: string, body: { [key: string]: any }): Promise<void>,
  editOriginalInteractionWithForm(token: string, body: FormData): Promise<void>,
  createMessage(channel: ChannelId, content: string, allowedMentions: string[]): Promise<MessageId>,
  editMessage(channel: ChannelId, messageId: MessageId, content: string, allowedMentions: string[]): Promise<void>,
  deleteMessage(channel: ChannelId, messageId: MessageId): Promise<void>,
  createChannel(guild_id: string, channelName: string, category: CategoryId, privateUsers?: UserId[], privateRoles?: RoleId[]): Promise<ChannelId>,
  deleteChannel(channelId: ChannelId): Promise<void>,
  getChannel(channelId: ChannelId): Promise<APIChannel>,
  reactToMessage(reaction: String, messageId: MessageId, channel: ChannelId): Promise<void>,
  getUsersReacted(reaction: String, messageId: MessageId, channel: ChannelId): Promise<UserId[]>,
  getMessagesInChannel(channelId: ChannelId, before?: MessageId): Promise<APIMessage[]>,
  createThreadInChannel(channel: ChannelId, channelName: string): Promise<ChannelId>,
  checkMessageExists(channel: ChannelId, messageId: MessageId): Promise<boolean>,
  getUsers(guild_id: string): Promise<APIGuildMember[]>,
  getGuildInformation(guild_id: string): Promise<APIGuild>,
  uploadEmoji(imageData: string, name: string): Promise<APIEmoji>,
  getBotUser(): UserId,
  retrieveAccessToken(code: string, redirect: string): Promise<string>,
  getUserGuilds(accessToken: string): Promise<APIGuild[]>,
  generateOAuthRedirect(redirct: string, scope: string, state: string): string
}

type DiscordSettings = { publicKey: string, botToken: string, appId: string, clientSecret?: string }
export function createClient(settings: DiscordSettings): DiscordClient {
  async function sendDiscordRequest(endpoint: string, options: { [key: string]: any }, maxTries: number = 10) {
    // append endpoint to root API URL
    const url = "https://discord.com/api/v10/" + endpoint
    if (options.body) options.body = JSON.stringify(options.body)
    let tries = 0
    while (tries < maxTries) {
      const res = await fetch(url, {
        headers: {
          Authorization: `Bot ${settings.botToken}`,
          "Content-Type": "application/json; charset=UTF-8",
        },
        ...options,
      })
      if (!res.ok) {
        const stringData = await res.text()
        let data: DiscordError = { message: "Snallabot Error, could not send to discord", code: 1 }
        try {
          data = JSON.parse(stringData) as DiscordError
        } catch (e) {
          tries = tries + 1
          await new Promise((r) => setTimeout(r, 1000))
        }
        if (data.retry_after) {
          tries = tries + 1
          const retryTime = data.retry_after
          await new Promise((r) => setTimeout(r, retryTime * 1000))
        } else {
          throw new DiscordRequestError(data)
        }
      } else {
        return res
      }
    }
    throw new Error("max tries reached")
  }

  async function sendDiscordRequestForm(endpoint: string, body: FormData, options: { [key: string]: any }, maxTries: number = 10) {
    // append endpoint to root API URL
    const url = "https://discord.com/api/v10/" + endpoint
    let tries = 0
    while (tries < maxTries) {
      const res = await fetch(url, {
        headers: {
          Authorization: `Bot ${settings.botToken}`,
          // "Content-Type": "multipart/form-data; charset=UTF-8",
        },
        body: body,
        ...options
      })
      if (!res.ok) {
        const stringData = await res.text()
        let data: DiscordError = { message: "Snallabot Error, could not send to discord", code: 1 }
        try {
          data = JSON.parse(stringData) as DiscordError
        } catch (e) {
          tries = tries + 1
          await new Promise((r) => setTimeout(r, 1000))
        }
        if (data.retry_after) {
          tries = tries + 1
          const retryTime = data.retry_after
          await new Promise((r) => setTimeout(r, retryTime * 1000))
        } else {
          throw new DiscordRequestError(data)
        }
      } else {
        return res
      }
    }
    throw new Error("max tries reached")
  }

  async function installCommand(command: RESTPostAPIApplicationCommandsJSONBody, guildId?: string) {
    const endpoint = guildId ? `applications/${settings.appId}/guilds/${guildId}/commands` : `applications/${settings.appId}/commands`
    await sendDiscordRequest(endpoint, { method: "POST", body: command })
  }

  async function deleteCommand(command: RESTPostAPIApplicationCommandsJSONBody, guildId?: string) {
    const getEndpoint = guildId ? `applications/${settings.appId}/guilds/${guildId}/commands` : `applications/${settings.appId}/commands`
    const getCommandResponse = await sendDiscordRequest(getEndpoint, { method: "GET" })
    const commands = await getCommandResponse.json() as APIApplicationCommand[]
    const commandsToBeDeleted = commands.filter(c => c.name === command.name)
      .map(c => c.id)
    await Promise.all(commandsToBeDeleted.map(async (c) => {
      const deleteEndpoint = guildId ? `applications/${settings.appId}/guilds/${guildId}/commands/${c}` : `applications/${settings.appId}/commands/${c}`
      await sendDiscordRequest(deleteEndpoint, { method: "DELETE" })
    }))
  }

  return {
    interactionVerifier: async (ctx: ParameterizedContext) => {
      const signature = ctx.get("x-signature-ed25519")
      const timestamp = ctx.get("x-signature-timestamp")
      return await verifyKey(
        ctx.request.rawBody,
        signature,
        timestamp,
        settings.publicKey
      )

    },
    handleSlashCommand: async (mode: CommandMode, command: RESTPostAPIApplicationCommandsJSONBody, guildId?: string) => {
      if (mode === CommandMode.INSTALL) {
        await installCommand(command, guildId)
      } else if (mode === CommandMode.DELETE) {
        await deleteCommand(command, guildId)
      } else {
        throw new Error("invalid mode " + mode)
      }
    },
    editOriginalInteraction: async (token: string, body: { [key: string]: any }) => {
      try {
        await sendDiscordRequest(`webhooks/${settings.appId}/${token}/messages/@original`, { method: "PATCH", body })
      } catch (e) {
        throw e
      }
    },
    editOriginalInteractionWithForm: async (token: string, body: FormData) => {
      try {
        await sendDiscordRequestForm(`webhooks/${settings.appId}/${token}/messages/@original`, body, { method: "PATCH" })
      } catch (e) {
      }
    }
    ,
    createMessage: async (channel: ChannelId, content: string, allowedMentions = []): Promise<MessageId> => {
      try {
        const res = await sendDiscordRequest(`channels/${channel.id}/messages`, {
          method: "POST",
          body: {
            content: content,
            allowed_mentions: {
              parse: allowedMentions
            }
          }
        })
        const message = await res.json() as APIMessage
        return {
          id: message.id, id_type: DiscordIdType.MESSAGE
        }
      }
      catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permission to create a message in <#${channel.id}>`)
          }
          else if (e.code === UNKNOWN_MESSAGE) {
            throw new SnallabotDiscordError(e, `Snallabot cannot create message, it may have been deleted? Try to re-configure the featuer you just used. Full discord error ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL) {
            throw new SnallabotDiscordError(e, `Snallabot cannot create message in channel because the channel (<#${channel.id}>) may have been deleted? Try to re-configure the feature you just used. Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    editMessage: async (channel: ChannelId, messageId: MessageId, content: string, allowedMentions = []): Promise<void> => {
      try {
        await sendDiscordRequest(`channels/${channel.id}/messages/${messageId.id}`, {
          method: "PATCH",
          body: {
            content: content,
            allowed_mentions: {
              parse: allowedMentions
            }
          }
        })
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to edit message in channel <#${channel.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_MESSAGE) {
            throw new SnallabotDiscordError(e, `Snallabot cannot edit message, it may have been deleted? Full discord error ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL) {
            throw new SnallabotDiscordError(e, `Snallabot cannot edit message in channel because the channel (<#${channel.id}>) may have been deleted? Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    deleteMessage: async (channel: ChannelId, messageId: MessageId): Promise<void> => {
      try {
        await sendDiscordRequest(`channels/${channel.id}/messages/${messageId.id}`, {
          method: "DELETE"
        })
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to delete message in channel <#${channel.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_MESSAGE) {
            throw new SnallabotDiscordError(e, `Snallabot cannot delete message, it may have been deleted? Full discord error ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL) {
            throw new SnallabotDiscordError(e, `Snallabot cannot delete message in channel because the channel (<#${channel.id}>) may have been deleted? Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    createChannel: async (guild_id: string, channelName: string, category: CategoryId, privateUsers?: UserId[], privateRoles?: RoleId[]): Promise<ChannelId> => {
      try {
        const permissionOverwrites: any[] = []

        // If we have private users or roles, we need to set up permission overwrites
        if (privateUsers?.length || privateRoles?.length) {
          // First, deny @everyone access to the channel
          permissionOverwrites.push({
            id: guild_id, // @everyone role has the same ID as the guild
            type: 0, // Role type
            deny: "3072", // VIEW_CHANNEL (1024) + SEND_MESSAGES (2048) = 3072
          });

          // Allow specific users
          if (privateUsers?.length) {
            for (const user of privateUsers) {
              permissionOverwrites.push({
                id: user.id,
                type: 1, // Member type
                allow: "3072", // VIEW_CHANNEL (1024) + SEND_MESSAGES (2048) = 3072
              });
            }
          }

          // Allow specific roles
          if (privateRoles?.length) {
            for (const role of privateRoles) {
              permissionOverwrites.push({
                id: role.id,
                type: 0, // Role type
                allow: "3072", // VIEW_CHANNEL (1024) + SEND_MESSAGES (2048) = 3072
              });
            }
          }

          const botUserId = settings.appId
          permissionOverwrites.push({
            id: botUserId,
            type: 1, // Member type
            allow: "3072", // VIEW_CHANNEL (1024) + SEND_MESSAGES (2048) = 3072
          });
        }
        const res = await sendDiscordRequest(`guilds/${guild_id}/channels`, {
          method: "POST",
          body: {
            type: ChannelType.GuildText,
            name: channelName,
            parent_id: category.id,
            permission_overwrites: permissionOverwrites
          },
        })
        const channel = await res.json() as APIChannel
        return { id: channel.id, id_type: DiscordIdType.CHANNEL }
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to create channel under category <#${category.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL) {
            throw new SnallabotDiscordError(e, `Snallabot could not create channel under category (<#${category.id}>) may have been deleted? Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    deleteChannel: async (channel: ChannelId) => {
      try {
        await sendDiscordRequest(`/channels/${channel.id}`, { method: "DELETE" })
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to delete channel <#${channel.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL) {
            throw new SnallabotDiscordError(e, `Snallabot could not delete channel <#${channel.id}> may have been deleted? Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    reactToMessage: async (reaction: String, message: MessageId, channel: ChannelId): Promise<void> => {
      try {
        await sendDiscordRequest(`channels/${channel.id}/messages/${message.id}/reactions/${reaction}/@me`, { method: "PUT" })
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to react to message in  channel <#${channel.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL || e.code === UNKNOWN_MESSAGE) {
            throw new SnallabotDiscordError(e, `Snallabot could not react to message in channel <#${channel.id}>. the channel or the message may have been deleted? Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    getUsersReacted: async (reaction: string, message: MessageId, channel: ChannelId): Promise<UserId[]> => {
      try {
        const res = await sendDiscordRequest(
          `channels/${channel.id}/messages/${message.id}/reactions/${reaction}`,
          { method: "GET" }
        )
        const reactedUsers = await res.json() as APIUser[]
        return reactedUsers.filter(u => u.id !== settings.appId).map(u => ({ id: u.id, id_type: DiscordIdType.USER }))
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to see users reacted to message in  channel <#${channel.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL || e.code === UNKNOWN_MESSAGE) {
            throw new SnallabotDiscordError(e, `Snallabot could not have permissions to see users reacted to message in <#${channel.id}>. the channel or the message may have been deleted? Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    getMessagesInChannel: async function(channelId: ChannelId, before?: MessageId): Promise<APIMessage[]> {
      const requestUrl = `/channels/${channelId.id}/messages?limit=100${before ? "&before=" + before.id : ""}`
      try {
        const res = await sendDiscordRequest(requestUrl, { method: "GET" })
        return await res.json() as APIMessage[]
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to get messages from  <#${channelId.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL || e.code === UNKNOWN_MESSAGE) {
            throw new SnallabotDiscordError(e, `Snallabot could not get messages from  <#${channelId.id}>. the channel may have been deleted? Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    createThreadInChannel: async function(channel: ChannelId, threadName: string): Promise<ChannelId> {
      try {
        const res = await sendDiscordRequest(`channels/${channel.id}/threads`, {
          method: "POST",
          body: {
            name: threadName,
            auto_archive_duration: 60,
            type: 11,
          }
        })
        const thread = (await res.json()) as APIThreadChannel
        const threadId = thread.id
        return { id: threadId, id_type: DiscordIdType.CHANNEL }
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to create thread in  <#${channel.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL || e.code === UNKNOWN_MESSAGE) {
            throw new SnallabotDiscordError(e, `Snallabot could not create a thread in  <#${channel.id}>. the channel may have been deleted? Full discord error: ${e.message}`)
          }
        }
        throw e
      }

    },
    checkMessageExists: async function(channel: ChannelId, message: MessageId) {
      try {
        await sendDiscordRequest(`channels/${channel.id}/messages/${message.id}`, {
          method: "GET",
        })
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to create thread in  <#${channel.id}>. Full discord error: ${e.message}`)
          } else if (e.code === UNKNOWN_CHANNEL || e.code === UNKNOWN_MESSAGE) {
            return false
          }
        }
        throw e
      }
      return true
    },
    getUsers: async function(guild_id: string) {
      try {
        const res = await sendDiscordRequest(
          `guilds/${guild_id}/members?limit=1000`,
          {
            method: "GET",
          }
        )
        return await res.json() as APIGuildMember[]
      } catch (e) {
        if (e instanceof DiscordRequestError) {
          if (e.isPermissionError()) {
            throw new SnallabotDiscordError(e, `Snallabot does not have permissions to get users so I can check their roles. Full discord error: ${e.message}`)
          }
        }
        throw e
      }
    },
    getChannel: async function(channel: ChannelId): Promise<APIChannel> {
      const channelInfoRes = await sendDiscordRequest(`channels/${channel.id}`, {
        method: "GET",
      })
      const channelInfo = (await channelInfoRes.json()) as APIChannel
      return channelInfo
    },
    getGuildInformation: async function(guildId: string) {
      const guildInfoRes = await sendDiscordRequest(`guilds/${guildId}`, {
        method: "GET",
      })
      const guildInfo = (await guildInfoRes.json()) as APIGuild
      return guildInfo
    },
    uploadEmoji: async function(image: string, name: string) {
      try {
        const res = await sendDiscordRequest(`applications/${settings.appId}/emojis`, {
          method: "POST",
          body: {
            name: name,
            image: image
          }
        })
        return (await res.json()) as APIEmoji;
      }
      catch (e) {
        if (e instanceof DiscordRequestError) {
          const errorData = e.originalError
          // Check for the specific duplicate emoji name error
          if (errorData.code === 50035 &&
            errorData.errors?.name?._errors?.[0]?.code === "APPLICATION_EMOJI_NAME_ALREADY_TAKEN") {

            // Get all existing emojis to find the one with the same name
            const existingEmojisRes = await sendDiscordRequest(`applications/${settings.appId}/emojis`, {
              method: "GET"
            });

            const existingEmojis = await existingEmojisRes.json() as { items: APIEmoji[] }
            const duplicateEmoji = existingEmojis.items.find((emoji) => emoji.name === name);

            if (duplicateEmoji) {
              // Delete the existing emoji
              await sendDiscordRequest(`applications/${settings.appId}/emojis/${duplicateEmoji.id}`, {
                method: "DELETE"
              });

              // Create the new emoji
              const newRes = await sendDiscordRequest(`applications/${settings.appId}/emojis`, {
                method: "POST",
                body: {
                  name: name,
                  image: image
                }
              });

              return (await newRes.json()) as APIEmoji;
            }
          }
        }
        // If it's a different error, throw it
        throw new Error(`Discord API Error: ${e}`);
      }
    },
    getBotUser: function() {
      return { id: settings.appId, id_type: DiscordIdType.USER }
    },
    retrieveAccessToken: async function(code: string, redirectUrl: string) {
      const secret = settings.clientSecret
      if (!secret) {
        throw new Error(`Missing Client Secret`)
      }
      const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: settings.appId,
          client_secret: secret,
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: redirectUrl,
        }),
      });

      const { access_token } = await tokenResponse.json();
      return access_token
    },
    getUserGuilds: async function(accessToken: string) {
      const userGuildsResponse = await fetch('https://discord.com/api/users/@me/guilds', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      const userGuilds = await userGuildsResponse.json() as APIGuild[]
      return userGuilds
    },
    generateOAuthRedirect: function(redirect: string, scope: string, state: string) {
      return `https://discord.com/api/oauth2/authorize?client_id=${settings.appId}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(state)}`;
    }
  }
}



export function respond(ctx: ParameterizedContext, body: any) {
  ctx.status = 200
  ctx.set("Content-Type", "application/json")
  ctx.body = body
}

export function createMessageResponse(content: string, options = {}) {
  return {
    type: InteractionResponseType.ChannelMessageWithSource,
    data: {
      content: content,
      ...options
    }
  }
}

export function deferMessage() {
  return {
    type: InteractionResponseType.DeferredChannelMessageWithSource,
  }
}

export function deferMessageInvisible() {
  return {
    type: InteractionResponseType.DeferredChannelMessageWithSource,
    data: { flags: 64 }
  }
}

export function formatTeamMessageName(discordId: string | undefined, gamerTag: string | undefined) {
  if (discordId) {
    return `<@${discordId}>`
  }
  if (gamerTag) {
    return gamerTag
  }
  return "CPU"
}

export enum SnallabotReactions {
  SCHEDULE = "%E2%8F%B0",
  GG = "%F0%9F%8F%86",
  HOME = "%F0%9F%8F%A0",
  AWAY = "%F0%9F%9B%AB",
  SIM = "%E2%8F%AD%EF%B8%8F",
}

export enum SnallabotCommandReactions {
  LOADING = "<a:5956loadingghostss:1450565253313200269>",
  WAITING = "<a:3393waiting:1450565250754809987>",
  FINISHED = "<a:32423check:1450565254600986715>",
  ERROR = "<:4561pinkerror:1450565251891200062>"
}

export enum ResponseType {
  COMMAND,
  INTERACTION
}
export function createProdClient() {
  if (!process.env.PUBLIC_KEY) {
    throw new Error("No Public Key passed for interaction verification")
  }

  if (!process.env.DISCORD_TOKEN) {
    throw new Error("No Discord Token passed for interaction verification")
  }
  if (!process.env.APP_ID) {
    throw new Error("No App Id passed for interaction verification")
  }

  const prodSettings = { publicKey: process.env.PUBLIC_KEY, botToken: process.env.DISCORD_TOKEN, appId: process.env.APP_ID, clientSecret: process.env.CLIENT_SECRET }
  return createClient(prodSettings)
}

export enum SnallabotTeamEmojis {
  // AFC East
  NE = "<:ne:1450565344824393929>",
  NYJ = "<:nyj:1450565352000978955>",
  BUF = "<:buf:1450565321290154065>",
  MIA = "<:mia:1450565341955620974>",

  // AFC North
  CIN = "<:cin:1450565325077876882>",
  PIT = "<:pit:1450565355201232896>",
  BAL = "<:bal:1450565319784403037>",
  CLE = "<:cle:1450565325996163102>",

  // AFC South
  TEN = "<:ten:1450565366693625856>",
  IND = "<:ind:1450565333239730249>",
  JAX = "<:jax:1450565334527643709>",
  HOU = "<:hou:1450565331377721395>",

  // AFC West
  KC = "<:kc:1450565335618158692>",
  LV = "<:lv:1450565340806517019>",
  DEN = "<:den:1450565327585804308>",
  LAC = "<:lac:1450565337375309834>",

  // NFC East
  DAL = "<:dal:1450565326772113479>",
  NYG = "<:nyg:1450565350482645084>",
  PHI = "<:phi:1450565353791815834>",
  WAS = "<:was:1450565367889002507>",

  // NFC North
  MIN = "<:min:1450565343444598795>",
  CHI = "<:chi:1450565323924312288>",
  DET = "<:det:1450565328596635751>",
  GB = "<:gb:1450565330236608743>",

  // NFC South
  NO = "<:no:1450565347768795286>",
  CAR = "<:car:1450565322774941849>",
  TB = "<:tb:1450565365255114914>",
  ATL = "<:atl:1450565318924566718>",

  // NFC West
  ARI = "<:ari:1450565316651257998>",
  LAR = "<:lar:1450565339309015265>",
  SEA = "<:sea:1450565356178378886>",
  SF = "<:sf:1450565363883573270>",
  // Default, NFL logo
  NFL = "<:nfl:1450565346087010354>"
}

export function getTeamEmoji(teamAbbr: string, leagueCustomLogos: LeagueLogos): string {
  const customLogo = leagueCustomLogos[teamAbbr]
  if (customLogo) {
    return `<:${customLogo.emoji_name}:${customLogo.emoji_id}>`
  }
  return SnallabotTeamEmojis[teamAbbr.toUpperCase() as keyof typeof SnallabotTeamEmojis] || SnallabotTeamEmojis.NFL
}
export function formatTeamEmoji(leagueCustomLogos: LeagueLogos, teamAbbr?: string) {
  if (teamAbbr) {
    return getTeamEmoji(teamAbbr, leagueCustomLogos)
  }
  return SnallabotTeamEmojis.NFL
}

export function formatGame(game: MaddenGame, teams: TeamList, leagueCustomLogos: LeagueLogos) {
  const awayTeam = teams.getTeamForId(game.awayTeamId)
  const homeTeam = teams.getTeamForId(game.homeTeamId)
  const awayEmoji = formatTeamEmoji(leagueCustomLogos, awayTeam?.abbrName)
  const homeEmoji = formatTeamEmoji(leagueCustomLogos, homeTeam?.abbrName)
  const awayDisplay = `${awayEmoji} ${awayTeam?.displayName}`;
  const homeDisplay = `${homeEmoji} ${homeTeam?.displayName}`;

  if (game.status === GameResult.NOT_PLAYED) {
    return `${awayDisplay} vs ${homeDisplay}`;
  } else {
    if (game.awayScore > game.homeScore) {
      return `**${awayDisplay} ${game.awayScore}** vs ${game.homeScore} ${homeDisplay}`;
    } else if (game.homeScore > game.awayScore) {
      return `${awayDisplay} ${game.awayScore} vs **${game.homeScore} ${homeDisplay}**`;
    }
    return `${awayDisplay} ${game.awayScore} vs ${game.homeScore} ${homeDisplay}`;
  }
}

export async function getSimsForWeek(leagueId: string, week: number, seasonIndex: number) {
  const sims = await EventDB.queryEvents<ConfirmedSimV2>(leagueId, "CONFIRMED_SIM", new Date(0), { week: week, seasonIndex: seasonIndex }, 30)
  const simGames = await MaddenDB.getGamesForSchedule(leagueId, sims.map(s => ({ id: s.scheduleId, week: s.week, season: s.seasonIndex })))
  const convertedSims = sims.map((s, simIndex) => ({ ...s, scheduleId: simGames[simIndex].scheduleId }))
  return convertedSims
}

export async function getSims(leagueId: string, seasonIndex?: number) {
  const sims = seasonIndex != null ? await EventDB.queryEvents<ConfirmedSimV2>(leagueId, "CONFIRMED_SIM", new Date(0), { seasonIndex: seasonIndex }, 5000) : await EventDB.queryEvents<ConfirmedSimV2>(leagueId, "CONFIRMED_SIM", new Date(0), {}, 5000)
  const simGames = await MaddenDB.getGamesForSchedule(leagueId, sims.map(s => ({ id: s.scheduleId, week: s.week, season: s.seasonIndex })))
  const convertedSims = sims.map((s, simIndex) => ({ ...s, scheduleId: simGames[simIndex].scheduleId }))
  return convertedSims
}

function createSimMessage(sim: ConfirmedSimV2): string {
  if (sim.result === SimResult.FAIR_SIM) {
    return "Fair Sim"
  } else if (sim.result === SimResult.FORCE_WIN_AWAY) {
    return "Force Win Away"
  } else if (sim.result === SimResult.FORCE_WIN_HOME) {
    return "Force Win Home"
  }
  throw new Error("Should not have gotten here! from createSimMessage")
}

export function createSimMessageForTeam(sim: ConfirmedSimV2, game: MaddenGame, selectedTeamId: number, teams: TeamList): string {
  const isTeamAway = teams.getTeamForId(game.awayTeamId).teamId === selectedTeamId
  if (sim.result === SimResult.FAIR_SIM) {
    return "FS"
  } else if (sim.result === SimResult.FORCE_WIN_AWAY) {
    return isTeamAway ? "FW" : "FL"
  } else if (sim.result === SimResult.FORCE_WIN_HOME) {
    return isTeamAway ? "FL" : "FW"
  }
  throw new Error("Should not have gotten here! from createSimMessage")
}

export function formatSchedule(week: number, seasonIndex: number, games: MaddenGame[], teams: TeamList, sims: ConfirmedSimV2[], logos: LeagueLogos) {
  const gameToSim = new Map<number, ConfirmedSimV2>()
  sims.forEach(sim => gameToSim.set(sim.scheduleId, sim))
  const scoreboardGames = games.sort((g1, g2) => g1.scheduleId - g2.scheduleId).map(game => {
    const simMessage = gameToSim.has(game.scheduleId) ? `(${createSimMessage(gameToSim.get(game.scheduleId)!)})` : ""
    const gameMessage = formatGame(game, teams, logos)
    return `${gameMessage} ${simMessage}`
  }).join("\n")
  return `# ${seasonIndex + MADDEN_SEASON} Season ${getMessageForWeek(week)} Games\n${scoreboardGames}`
}
