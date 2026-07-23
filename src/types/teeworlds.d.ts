declare module 'teeworlds' {
  export class Client {
    constructor(host: string, port: number, nickname: string, options?: any);
    
    on(event: string, listener: (...args: any[]) => void): this;
    connect(): Promise<void>;
    Disconnect(): void;
    
    game: {
      SetTeam(team: number): void;
      Say(message: string, team?: boolean): void;
      Kill(): void;
      Emote(emote: number): void;
      Ping(): Promise<number>;
      ChangePlayerInfo(info: any): void;
      CallVoteOption(value: string, reason: string): void;
      CallVoteKick(playerId: string | number, reason: string): void;
      CallVoteSpectate(playerId: string | number, reason: string): void;
    };
    
    movement: {
      SetAim(x: number, y: number): void;
      Jump(state?: boolean): void;
      Fire(): void;
      Hook(state?: boolean): void;
      RunLeft(): void;
      RunRight(): void;
      RunStop(): void;
      Reset(): void;
    };
    
    rcon: {
      auth(password: string): void;
      auth(username: string, password: string): void;
      rcon(command: string | string[]): void;
      on(event: string, listener: (...args: any[]) => void): this;
    };
    
    SnapshotUnpacker: {
      getObjCharacter(id: number): any;
      getObjPlayerInfo(id: number): any;
      getObjClientInfo(id: number): any;
      OwnID: number | undefined;
    };
  }
  
  export interface ClientInfo {
    name: string;
    clan: string;
    country: number;
    skin: string;
    use_custom_color: number;
    color_body: number;
    color_feet: number;
  }
}