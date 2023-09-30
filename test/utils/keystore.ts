import { ECCKeyStore } from "../../src/ecc/keystore";
import { RSAKeyStore } from "../../src/rsa/keystore";
import config from "../../src/config";
import idb from "../../src/idb";
import { KeyStore } from "../../src/types";
import { mock } from "./mock";
import {
  DEFAULT_EXCHANGE_KEY_NAME,
  DEFAULT_WRITE_KEY_NAME,
} from "../../src/constants";
import rsaKeys from "../../src/rsa/keys";
import eccKeys from "../../src/ecc/keys";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Mock = {
  mod: any;
  meth: string;
  resp: any;
  params: any;
};

type KeystoreMethodOpts = {
  desc: string;
  type: "ecc" | "rsa";
  mocks: Mock[];
  reqFn: (ks: KeyStore) => Promise<any>;
  expectedResp?: any;
};
/* eslint-enable @typescript-eslint/no-explicit-any */

export const keystoreMethod = (opts: KeystoreMethodOpts): void => {
  describe(opts.desc, () => {
    const fakes = [] as jest.SpyInstance[];
    let fakeMake: jest.SpyInstance;
    let fakeCreateifDNE: jest.SpyInstance;
    let response: any; // eslint-disable-line @typescript-eslint/no-explicit-any

    beforeAll(async () => {
      jest.resetAllMocks();
      jest.spyOn(idb, "getKeypair").mockImplementation((keyName) => {
        return keyName === "exchange-key" ? mock.keys : mock.writeKeys;
      });

      const keys = opts.type === "ecc" ? eccKeys : rsaKeys;
      fakeMake = jest.spyOn(keys, "makeKeypair");
      fakeMake.mockResolvedValue(mock.keys);

      fakeCreateifDNE = jest.spyOn(idb, "createIfDoesNotExist");
      fakeCreateifDNE.mockImplementation((_name, makeFn) => {
        makeFn();
      });

      opts.mocks.forEach((mock) => {
        const fake = jest.spyOn(mock.mod, mock.meth);
        fake.mockResolvedValue(mock.resp);
        fakes.push(fake);
      });

      const ks =
        opts.type === "ecc"
          ? new ECCKeyStore(config.defaultConfig, mock.idbStore)
          : new RSAKeyStore(config.defaultConfig, mock.idbStore);
      ks.addKeypair(DEFAULT_WRITE_KEY_NAME, DEFAULT_EXCHANGE_KEY_NAME);
      response = await opts.reqFn(ks);
    });

    opts.mocks.forEach((mock, i) => {
      it(`should call ${mock.meth} once`, () => {
        expect(fakes[i]).toBeCalledTimes(1);
      });

      it(`should call the library function with the expected params`, () => {
        expect(fakes[i].mock.calls[0]).toEqual(mock.params);
      });
    });

    if (opts.expectedResp !== undefined) {
      it("should return the expectedResp", () => {
        expect(response).toEqual(opts.expectedResp);
      });
    }
  });
};
