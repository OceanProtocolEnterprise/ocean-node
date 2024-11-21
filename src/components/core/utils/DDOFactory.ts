import { DDO } from '../../../@types/DDO/DDO'
import { VerifiableCredential } from '../../../@types/DDO/VerifiableCredential'
import { Service } from '../../../@types/DDO/Service'
import { Metadata } from '../../../@types/DDO/Metadata'
import { Credentials } from '../../../@types/DDO/Credentials'
import { Event } from '../../../@types/DDO/Event'
import { validateObject } from './validateDdoHandler.js'

interface ExtractedDDOFields {
  did: string
  nftAddress: string
  chainId: number
  services: Service[]
  metadata: Metadata
  credentials: Credentials
  event: Event
}

class DDOProcessorV4 {
  extractDDOFields(ddo: DDO): ExtractedDDOFields {
    return {
      did: ddo.id,
      nftAddress: ddo.nftAddress,
      chainId: ddo.chainId,
      services: ddo.services,
      metadata: ddo.metadata,
      credentials: ddo.credentials,
      event: ddo.event
    }
  }

  async validateDDO(ddo: DDO): Promise<[boolean, Record<string, string[]>]> {
    return await validateObject(ddo, ddo.chainId, ddo.nftAddress)
  }
}

class DDOProcessorV5 {
  extractDDOFields(ddo: VerifiableCredential): ExtractedDDOFields {
    return {
      did: ddo.credentialSubject.id,
      nftAddress: ddo.credentialSubject.nftAddress,
      chainId: ddo.credentialSubject.chainId,
      services: ddo.credentialSubject.services,
      metadata: ddo.credentialSubject.metadata,
      credentials: ddo.credentialSubject.credentials,
      event: ddo.credentialSubject.event
    }
  }

  async validateDDO(ddo: any): Promise<[boolean, Record<string, string[]>]> {
    return await validateObject(
      ddo,
      ddo.credentialSubject.chainId,
      ddo.credentialSubject.nftAddress
    )
  }
}

export class DDOProcessorFactory {
  static createProcessor(ddo: any): DDOProcessorV5 | DDOProcessorV4 {
    switch (ddo.version) {
      case '4.1.0':
      case '4.3.0':
      case '4.5.0':
        return new DDOProcessorV4()

      case '5.0.0':
        return new DDOProcessorV5()

      default:
        throw new Error(`Unsupported DDO version: ${ddo.version}`)
    }
  }
}
