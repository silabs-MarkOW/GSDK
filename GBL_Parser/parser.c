#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "parser.h"

int32_t parser_parse(void                              *context,
                     ImageProperties_t                 *imageProperties,
                     uint8_t                           buffer[],
                     size_t                            length,
                     const BootloaderParserCallbacks_t *callbacks)
{
  ParserContext_t *parserContext = (ParserContext_t *)context;
  EblInputBuffer_t input = {
			    .buffer = buffer,
			    .length = length,
			    .offset = 0UL
  };
  uint8_t tagBuffer[EBL_PARSER_BUFFER_SIZE];
#ifdef BTL_PARSER_SUPPORT_EBLV2
  uint16_t temporaryShort;
#endif
  uint32_t temporaryWord;
  int32_t retval;
  EblTagHeader_t eblTagHeader;
  const GblCustomTag_t *customTag = NULL;
  size_t   tmpSize;

  // This is pretty much purely a state machine...
  while (input.offset < length) {
#if defined(__ICCARM__)
    // Suppress MISRA warning that default case is missing
#pragma diag_suppress=Pm058
#endif
    switch (parserContext->internalState) {
      // Coming from an idle state means starting anew
      // Which means we're expecting a header tag
    case EblParserStateInit:
      // Peek into buffer to set EBLv2 parsing mode if necessary and allowed
#ifdef BTL_PARSER_SUPPORT_EBLV2
      // We always expect word-sized input, so peeking into
      // the first two bytes here is fine.
      temporaryShort = EBL_PARSER_ARRAY_TO_U16(buffer, 0);
      if (temporaryShort == EBLV2_TAG_ID_HEADER) {
	parserContext->flags |= PARSER_FLAG_IS_EBLV2;
      }
#endif

      // First, get tag/length combo
      retval = ebl_parseHeader(parserContext,
			       &input,
			       &eblTagHeader);

      if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	return retval;
      }

      // Save length of this tag
      parserContext->lengthOfTag = eblTagHeader.length;
      parserContext->offsetInTag = 0UL;

      if (eblTagHeader.tagId == EBL_TAG_ID_HEADER_V3) {
	parserContext->internalState = EblParserStateHeader;
      }
#ifdef BTL_PARSER_SUPPORT_EBLV2
      else if ((eblTagHeader.tagId == EBLV2_TAG_ID_HEADER)
	       && (parserContext->flags & PARSER_FLAG_IS_EBLV2)) {
	parserContext->internalState = EblParserStateHeaderV2;
      }
#endif
      else {
	parserContext->internalState = EblParserStateError;
	return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
      }

      break;

      // We've already got the EBL Header tag, and are done with whatever
      // tag we were processing. Now waiting for a new tag.
    case EblParserStateIdle:
      // First, get tag/length combo, for which we need 8 bytes
      retval = ebl_parseHeader(parserContext,
			       &input,
			       &eblTagHeader);

      if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	return retval;
      }

      // Check for unexpected tag after signature
      if (parserContext->gotSignature) {
	if (eblTagHeader.tagId == EBL_TAG_ID_END) {
	  parserContext->internalState = EblParserStateFinalize;
	} else {
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	}
	break;
      }

#ifndef BTL_PARSER_NO_SUPPORT_ENCRYPTION
      // Check tagBuffer for valid tag/length
      if ((parserContext->flags & PARSER_FLAG_ENCRYPTED)
	  && (!(parserContext->inEncryptedContainer))) {
	switch (eblTagHeader.tagId) {
	case EBL_TAG_ID_ENC_INIT:
	  parserContext->internalState = EblParserStateEncryptionInit;
	  break;
	case EBL_TAG_ID_ENC_EBL_DATA:
	  parserContext->internalState = EblParserStateEncryptionContainer;
	  parserContext->lengthOfEncryptedTag = parserContext->lengthOfTag;
	  parserContext->offsetInEncryptedTag = 0UL;
	  break;
	case EBL_TAG_ID_ENC_MAC:
	  // MAC is no longer supported
	  // Now we rely on ECDSA signing instead
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_UNKNOWN_TAG;
	  break;
#if defined(BTL_SUPPORT_CERTIFICATES)
	case EBL_TAG_ID_CERTIFICATE_ECDSA_P256:
	  parserContext->internalState = EblParserStateCertificate;
	  break;
#endif
	case EBL_TAG_ID_SIGNATURE_ECDSA_P256:
	  parserContext->internalState = EblParserStateSignature;
	  break;
	case EBL_TAG_ID_END:
	  // Don't allow ending the EBL without a signature if not
	  // explicitly configured to do so
	  if (parser_requireAuthenticity()) {
	    parserContext->internalState = EblParserStateError;
	    return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	  }
	  parserContext->internalState = EblParserStateFinalize;
	  break;
	case EBL_TAG_ID_BOOTLOADER:
	case EBL_TAG_ID_APPLICATION:
	case EBL_TAG_ID_SE_UPGRADE:
	case EBL_TAG_ID_METADATA:
	case EBL_TAG_ID_PROG:
	case EBL_TAG_ID_ERASEPROG:
	case EBL_TAG_ID_HEADER_V3:
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	  break;
	default:
	  parserContext->internalState = EblParserStateError;
	  if (gbl_isCustomTag(&eblTagHeader)) {
	    // Custom tag exists, so it's unexpected rather than unknown
	    return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	  } else {
	    return BOOTLOADER_ERROR_PARSER_UNKNOWN_TAG;
	  }
	  break;
	}
      } else {
#endif // BTL_PARSER_NO_SUPPORT_ENCRYPTION
#ifdef BTL_PARSER_SUPPORT_EBLV2
        if (parserContext->flags & PARSER_FLAG_IS_EBLV2) {
          // Translate V2 tag ID into V3 equivalent
          switch (eblTagHeader.tagId) {
	  case EBLV2_TAG_ID_METADATA:
	    eblTagHeader.tagId = EBL_TAG_ID_METADATA;
	    break;
	  case EBLV2_TAG_ID_PROG:
	    eblTagHeader.tagId = EBL_TAG_ID_PROG;
	    break;
	  case EBLV2_TAG_ID_ERASEPROG:
	    eblTagHeader.tagId = EBL_TAG_ID_ERASEPROG;
	    break;
	  case EBLV2_TAG_ID_END:
	    eblTagHeader.tagId = EBL_TAG_ID_END;
	    break;
	  case EBLV2_TAG_ID_MFGPROG:
	    eblTagHeader.tagId = EBL_TAG_ID_PROG;
	    break;
	  default:
	    parserContext->internalState = EblParserStateError;
	    return BOOTLOADER_ERROR_PARSER_UNKNOWN_TAG;
          }
        }
#endif

        switch (eblTagHeader.tagId) {
#if defined(SEMAILBOX_PRESENT) || defined(CRYPTOACC_PRESENT)
	case EBL_TAG_ID_SE_UPGRADE:
	  parserContext->internalState = EblParserStateSe;
	  break;
#endif
	case EBL_TAG_ID_BOOTLOADER:
	  parserContext->internalState = EblParserStateBootloader;
	  break;
	case EBL_TAG_ID_APPLICATION:
	  parserContext->internalState = EblParserStateApplication;
	  break;
	case EBL_TAG_ID_METADATA:
	  parserContext->internalState = EblParserStateMetadata;
	  break;
	case EBL_TAG_ID_PROG:
	  parserContext->internalState = EblParserStateProg;
	  break;
	case EBL_TAG_ID_ERASEPROG:
	  parserContext->internalState = EblParserStateEraseProg;
	  break;
	case EBL_TAG_ID_END:
	  // Don't allow ending the EBL inside of an encrypted container
	  // Don't allow ending the EBL without a signature if not
	  // explicitly configured to do so
	  if ((parser_requireAuthenticity())
	      || (parserContext->inEncryptedContainer)) {
	    parserContext->internalState = EblParserStateError;
	    return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	  }

	  parserContext->internalState = EblParserStateFinalize;
	  break;
#if defined(BTL_SUPPORT_CERTIFICATES)
	case EBL_TAG_ID_CERTIFICATE_ECDSA_P256:
	  // Don't allow ending the EBL inside of an encrypted container
#ifndef BTL_PARSER_NO_SUPPORT_ENCRYPTION
	  if (parserContext->inEncryptedContainer) {
	    parserContext->internalState = EblParserStateError;
	    return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	  }
#endif
	  parserContext->internalState = EblParserStateCertificate;
	  break;
#endif
	case EBL_TAG_ID_SIGNATURE_ECDSA_P256:
	  // Don't allow ending the EBL inside of an encrypted container
#ifndef BTL_PARSER_NO_SUPPORT_ENCRYPTION
	  if (parserContext->inEncryptedContainer) {
	    parserContext->internalState = EblParserStateError;
	    return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	  }
#endif
	  parserContext->internalState = EblParserStateSignature;
	  break;
	case EBL_TAG_ID_HEADER_V3:
          // EBLv3: Header tag is always the first, never encrypted, and
          // one EBL file never contains two headers.
	default:
	  if (gbl_isCustomTag(&eblTagHeader)) {
	    // Custom tag exists
	    parserContext->customTagId = eblTagHeader.tagId;
	    parserContext->internalState = EblParserStateCustomTag;
	    customTag = gbl_getCustomTagProperties(eblTagHeader.tagId);
	    if ((parserContext->flags & PARSER_FLAG_PARSE_CUSTOM_TAGS)
		&& customTag && (customTag->enterTag)) {
	      retval = customTag->enterTag(parserContext);
	      if (retval != BOOTLOADER_OK) {
		return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	      }
	    }
	  } else {
	    parserContext->internalState = EblParserStateError;
	    if (parserContext->inEncryptedContainer) {
	      // Getting an unknown tag inside of encrypted container is most
	      // probably due to lacking the correct decryption key
	      return BOOTLOADER_ERROR_PARSER_KEYERROR;
	    } else {
	      return BOOTLOADER_ERROR_PARSER_UNKNOWN_TAG;
	    }
	  }
	  break;
        }
#ifndef BTL_PARSER_NO_SUPPORT_ENCRYPTION
	// *INDENT-OFF*
      }
      // *INDENT-ON*
#endif
      break;

      // Received a header tag, parse information from it.
    case EblParserStateHeader:
      // Get version, magic, app info
      while (parserContext->offsetInTag < 8UL) {
	// Get data
	// Header should be hashed, but never decrypted
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     8UL,
			     true,
			     false);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	// 8 bytes:
	// - u32 version
	// - u32 type

	temporaryWord = EBL_PARSER_ARRAY_TO_U32(tagBuffer, 0);
	if ((temporaryWord & 0xFF000000UL)
	    != EBL_COMPATIBILITY_MAJOR_VERSION) {
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_VERSION;
	}

	temporaryWord = EBL_PARSER_ARRAY_TO_U32(tagBuffer, 4);

#ifndef BTL_PARSER_NO_SUPPORT_ENCRYPTION
	if ((temporaryWord & EBL_TYPE_ENCRYPTION_AESCCM) != 0U) {
	  parserContext->flags |= PARSER_FLAG_ENCRYPTED;
	  BTL_DEBUG_PRINTLN("Enc");
	} else if (parser_requireConfidentiality()) {
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_FILETYPE;
	} else {
	  // Unencrypted EBL is allowed
	}
#else
	// No encryption supported, but encrypted GBL given
	if ((temporaryWord & EBL_TYPE_ENCRYPTION_AESCCM) != 0U) {
	  return BOOTLOADER_ERROR_PARSER_FILETYPE;
	}
#endif

	if ((parser_requireAuthenticity())
	    && ((temporaryWord & EBL_TYPE_SIGNATURE_ECDSA) == 0U)) {
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_FILETYPE;
	}
      }

      parserContext->internalState = EblParserStateIdle;
      break;

      // Received a header tag, parse information from it.
    case EblParserStateHeaderV2:
#ifdef BTL_PARSER_SUPPORT_EBLV2
      // Get version, magic, app info
      while (parserContext->offsetInTag < 12UL) {
	// Get data
	// Header should be hashed, but never decrypted
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     12UL,
			     true,
			     false);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	// 12 bytes:
	// - u16 version
	// - u16 magic word
	// - u32 flashAddr
	// - u32 aatCrc

	temporaryShort = EBL_PARSER_ARRAY_TO_U16(tagBuffer, 0);
	temporaryShort = (uint16_t) __REV16((uint32_t)temporaryShort);
	if (((uint32_t)temporaryShort & 0xFF00U)
	    != EBLV2_COMPATIBILITY_MAJOR_VERSION) {
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_VERSION;
	}

	temporaryShort = EBL_PARSER_ARRAY_TO_U16(tagBuffer, 2);
	temporaryShort = (uint16_t) __REV16((uint32_t)temporaryShort);
	if (temporaryShort != EBLV2_HEADER_MAGIC) {
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	}

	parserContext->programmingAddress =
	  __REV(EBL_PARSER_ARRAY_TO_U32(tagBuffer, 4));

	// Use tagAddress as AAT CRC field in V2 parsing,
	// and withheldBootloaderVectors to store the end CRC,
	// since we'll never need either of these fields in V2 parsing
	memcpy(parserContext->withheldBootloaderVectors, &tagBuffer[8], 4U);
	parserContext->tagAddress = BTL_CRC32_START;
      }

      while (parserContext->offsetInTag < parserContext->lengthOfTag) {
	// Always parse minimum one word
	if (ebl_getBytesAvailable(parserContext, &input) < 4UL) {
	  (void)ebl_storeData(parserContext, &input);
	  return BOOTLOADER_OK;
	}
	// Set temporaryWord to offset into AAT buffer
	temporaryWord = parserContext->offsetInTag - 12U;

	retval = ebl_getData(parserContext,
			     &input,
			     tagBuffer,
			     4U,
			     true,
			     true);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	// AAT.type is at offset 16 in AAT
	if (temporaryWord != 16U) {
	  parserContext->tagAddress =
	    btl_crc32Stream(tagBuffer,
			    4U,
			    parserContext->tagAddress);
	} else {
	  uint8_t ff = 0xFFU;
	  // AAT.type gets FF'ed out in EBLv2 for AAT CRC calc
	  parserContext->tagAddress =
	    btl_crc32Stream(&ff, 1U, parserContext->tagAddress);
	  parserContext->tagAddress =
	    btl_crc32Stream(&ff, 1U, parserContext->tagAddress);
	  parserContext->tagAddress =
	    btl_crc32Stream(&tagBuffer[2], 1U, parserContext->tagAddress);
	  parserContext->tagAddress =
	    btl_crc32Stream(&tagBuffer[3], 1U, parserContext->tagAddress);
	}

	retval = gbl_writeProgData(parserContext, tagBuffer, 4U, callbacks);
	if (retval != BOOTLOADER_OK) {
	  parserContext->internalState = EblParserStateError;
	  return retval;
	}
      }

      // When done with AAT flashing, check AAT CRC
      temporaryWord =
	__REV(EBL_PARSER_ARRAY_TO_U32(parserContext->withheldBootloaderVectors, 0));
      if (parserContext->tagAddress != ~temporaryWord) {
	parserContext->internalState = EblParserStateError;
	return BOOTLOADER_ERROR_PARSER_CRC;
      }

      imageProperties->contents |= BTL_IMAGE_CONTENT_APPLICATION;
      parserContext->internalState = EblParserStateIdle;
#else
      // EBLv2 not supported
      parserContext->internalState = EblParserStateError;
      return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
#endif
      break;

    case EblParserStateApplication:
      while (parserContext->offsetInTag < parserContext->lengthOfTag) {
	// Get data
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     parserContext->lengthOfTag,
			     true,
			     true);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	// Received full application data struct
	(void) memcpy(&imageProperties->application,
		      tagBuffer,
		      sizeof(ApplicationData_t));

	imageProperties->contents |= BTL_IMAGE_CONTENT_APPLICATION;

	if (parser_applicationUpgradeValidCallback(&imageProperties->application) == false) {
	  // Application didn't check out
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_REJECTED;
	}
      }
      parserContext->internalState = EblParserStateIdle;
      break;

      // Received a tag with binary data to pass on.
      // If you have custom metadata in your EBL, we'll pass
      // it on to the application (through the bootloader).
      // Prog and Eraseprog tags are acted on by the bootloader.

#if defined(SEMAILBOX_PRESENT) || defined(CRYPTOACC_PRESENT)
    case EblParserStateSe:
      while (parserContext->offsetInTag < 8UL) {
	// Get data
	retval = ebl_getData(context,
			     &input,
			     &tagBuffer[8],
			     8UL,
			     true, /* Do SHA hashing */
			     true /* Decrypt if necessary */);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	imageProperties->contents |= BTL_IMAGE_CONTENT_SE;
	imageProperties->seUpgradeVersion =
	  EBL_PARSER_ARRAY_TO_U32(tagBuffer, 12);

	if (imageProperties->instructions & BTL_IMAGE_INSTRUCTION_SE) {
	  // Reinsert GBL tag header into data stream
	  tagBuffer[0] = 0xEBU;
	  tagBuffer[1] = 0x17U;
	  tagBuffer[2] = 0xA6U;
	  tagBuffer[3] = 0x5EU;

	  // Save GBL tag length as withheld data
	  memcpy(&parserContext->withheldBootloaderVectors, (void *)&parserContext->lengthOfTag, 4UL);

	  parserContext->tagAddress = 0UL;
	  parserContext->receivedFlags |= BTL_PARSER_RECEIVED_SE;

	  // Pass 4 first words to SE upgrade
	  if ((callbacks->bootloaderCallback != NULL)) {
	    // SE data
	    callbacks->bootloaderCallback(parserContext->tagAddress,
					  tagBuffer,
					  4U,
					  callbacks->context);
	    callbacks->bootloaderCallback(parserContext->tagAddress + 8U,
					  &tagBuffer[8],
					  8U,
					  callbacks->context);
	    parserContext->tagAddress += 16U;
	  }
	}

	parserContext->internalState = EblParserStateSeData;
      }
      break;
#endif
    case EblParserStateBootloader:
      while (parserContext->offsetInTag < 8UL) {
	// Get data
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     8UL,
			     true, /* Do SHA hashing */
			     true /* Decrypt if necessary */);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	imageProperties->contents |= BTL_IMAGE_CONTENT_BOOTLOADER;
	imageProperties->bootloaderVersion = EBL_PARSER_ARRAY_TO_U32(
								     tagBuffer,
								     0);
	imageProperties->bootloaderUpgradeSize = parserContext->lengthOfTag - 8U;

	// Sanity check bootloader base address
	temporaryWord = EBL_PARSER_ARRAY_TO_U32(tagBuffer, 4);

#if defined(BOOTLOADER_HAS_FIRST_STAGE)
	if (firstBootloaderTable->header.type
	    == BOOTLOADER_MAGIC_FIRST_STAGE) {
	  if (temporaryWord
	      != (uint32_t)(firstBootloaderTable->mainBootloader)) {
	    parserContext->internalState = EblParserStateError;
	    return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	  }
	}
#else
	if (temporaryWord != FLASH_BASE) {
	  // Bootloader has to start at beginning of flash
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	}
#endif
	parserContext->internalState = EblParserStateBootloaderData;
	parserContext->receivedFlags |= BTL_PARSER_RECEIVED_BOOTLOADER;
	parserContext->tagAddress = 0UL;
      }
      break;
    case EblParserStateProg:
    case EblParserStateEraseProg:
      while (parserContext->offsetInTag < 4UL) {
	// Get data
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     4UL,
			     true, /* Do SHA hashing */
			     true /* Decrypt if necessary */);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	temporaryWord = EBL_PARSER_ARRAY_TO_U32(tagBuffer, 0);

#ifdef BTL_PARSER_SUPPORT_EBLV2
	if (parserContext->flags & PARSER_FLAG_IS_EBLV2) {
	  temporaryWord = __REV(temporaryWord);
	}
#endif
	if (parserContext->lengthOfTag > 4UL) {
	  // Only set programmingAddress if the tag actually contains data
	  parserContext->programmingAddress = temporaryWord;
	}
      }
      parserContext->internalState = EblParserStateProgData;
      break;
    case EblParserStateMetadata:
      parserContext->tagAddress = 0UL;
      parserContext->internalState = EblParserStateMetadataData;
      break;
#if defined(SEMAILBOX_PRESENT) || defined(CRYPTOACC_PRESENT)
    case EblParserStateSeData:
#endif
    case EblParserStateProgData:
    case EblParserStateBootloaderData:
    case EblParserStateMetadataData:
      while (parserContext->offsetInTag < parserContext->lengthOfTag) {
	// Get amount of bytes left in this tag
	tmpSize = parserContext->lengthOfTag - parserContext->offsetInTag;

	// Check buffer size vs. bytes we want to parse
	if (tmpSize >= 4UL) {
	  // Always parse minimum one word
	  if (ebl_getBytesAvailable(parserContext, &input) < 4UL) {
	    (void) ebl_storeData(parserContext, &input);
	    return BOOTLOADER_OK;
	  }
	} else if (ebl_getBytesAvailable(parserContext, &input) < tmpSize) {
	  (void) ebl_storeData(parserContext, &input);
	  return BOOTLOADER_OK;
	} else {
	  // There is less than a word left of this tag, and we have it all
	}
	// The amount of data we're going to parse in this cycle equals
	// min(bytes in buffer, bytes left in tag, size of internal buffer)
	if (tmpSize > EBL_PARSER_BUFFER_SIZE) {
	  tmpSize = EBL_PARSER_BUFFER_SIZE;
	}
	if (tmpSize > ebl_getBytesAvailable(parserContext, &input)) {
	  tmpSize = ebl_getBytesAvailable(parserContext, &input);
	}

	// Make sure to read word-sized chunks from the buffer for as long
	// as possible.
	// We can safely do the rounding down since we already verified
	// there are 4+ bytes available, or we're at the end of the tag.
	if (tmpSize >= 4UL) {
	  tmpSize &= ~3UL;
	}

	// Consume data
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     tmpSize,
			     true,
			     true);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	// Push back data
	if ((parserContext->internalState == EblParserStateMetadataData)
	    && (callbacks->metadataCallback != NULL)) {
	  callbacks->metadataCallback(parserContext->tagAddress,
				      tagBuffer,
				      tmpSize,
				      callbacks->context);
	  parserContext->tagAddress += tmpSize;
	} else {
	  while (tmpSize < 4UL) {
	    tagBuffer[tmpSize] = 0xFFU;
	    tmpSize++;
	  }

	  if (parserContext->internalState == EblParserStateProgData) {
	    // Application data
	    retval = gbl_writeProgData(parserContext, tagBuffer, tmpSize, callbacks);
	    // TODO: Handle error
	  } else if ((parserContext->internalState == EblParserStateBootloaderData)
		     && (imageProperties->instructions & BTL_IMAGE_INSTRUCTION_BOOTLOADER)
		     && (callbacks->bootloaderCallback != NULL)) {
	    // Bootloader data
	    // If bootloader initial PC is in this call, store it and override
	    // to FF. Initial PC will be passed to the callback at the end
	    // when entire EBL is validated.
	    if ((parserContext->tagAddress <= 4UL)
		&& ((parserContext->tagAddress + tmpSize) >= 7UL)) {
	      uint32_t bufferedBtlPcAddress =
		((uint32_t)tagBuffer)
		+ (4UL - parserContext->tagAddress);
	      (void) memcpy(parserContext->withheldBootloaderVectors,
			    (void*)bufferedBtlPcAddress,
			    4U);
	      (void) memset((void*)bufferedBtlPcAddress,
			    0xFF,
			    4U);
	    }

	    callbacks->bootloaderCallback(parserContext->tagAddress,
					  tagBuffer,
					  tmpSize,
					  callbacks->context);
	    parserContext->tagAddress += tmpSize;
#if defined(SEMAILBOX_PRESENT) || defined(CRYPTOACC_PRESENT)
	  } else if ((parserContext->internalState == EblParserStateSeData)
		     && (imageProperties->instructions & BTL_IMAGE_INSTRUCTION_SE)
		     && (callbacks->bootloaderCallback != NULL)) {
	    // SE data
	    // Re-use the bootloader callback
	    callbacks->bootloaderCallback(parserContext->tagAddress,
					  tagBuffer,
					  tmpSize,
					  callbacks->context);
	    parserContext->tagAddress += tmpSize;
#endif
	  } else {
	    // Not a valid tag
	  }
	}
      }
      parserContext->internalState = EblParserStateIdle;
      break;

    case EblParserStateCustomTag:
      if (parserContext->flags & PARSER_FLAG_PARSE_CUSTOM_TAGS) {
	customTag = gbl_getCustomTagProperties(parserContext->customTagId);
	if (!customTag) {
	  // TODO: Fix error code
	  return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	}
      }

      while (parserContext->offsetInTag < parserContext->lengthOfTag) {
	if ((parserContext->flags & PARSER_FLAG_PARSE_CUSTOM_TAGS)
	    && customTag && (customTag->numBytesRequired)) {
	  tmpSize = customTag->numBytesRequired(parserContext);
	} else {
	  tmpSize = 1UL;
	}
	if (ebl_getBytesAvailable(parserContext, &input) < tmpSize) {
	  // Not enough data available
	  (void) ebl_storeData(parserContext, &input);
	  return BOOTLOADER_OK;
	}

	// The amount of data we're going to parse in this cycle equals
	// min(size of internal buffer, bytes left in tag, bytes in combined buffers)
	tmpSize = SL_MIN(EBL_PARSER_BUFFER_SIZE,
			 parserContext->lengthOfTag - parserContext->offsetInTag);
	tmpSize = SL_MIN(tmpSize, ebl_getBytesAvailable(parserContext, &input));

	// Consume data
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     tmpSize,
			     true,
			     true);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	if (parserContext->flags & PARSER_FLAG_PARSE_CUSTOM_TAGS) {
	  if (customTag && (customTag->parseTag)) {
	    retval = customTag->parseTag(parserContext,
					 tagBuffer,
					 tmpSize,
					 callbacks);
	    if (retval != BOOTLOADER_OK) {
	      return retval;
	    }
	  } else {
	    BTL_DEBUG_PRINTLN("No parse callback");
	    return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
	  }
	} else {
	  BTL_DEBUG_PRINTLN("Skipping tag");
	}
      }

      if (parserContext->flags & PARSER_FLAG_PARSE_CUSTOM_TAGS) {
	if (customTag && (customTag->exitTag)) {
	  retval = customTag->exitTag(parserContext, callbacks);
	  if (retval != BOOTLOADER_OK) {
	    return retval;
	  }
	}
      }

      parserContext->internalState = EblParserStateIdle;
      break;
      // Received an end tag, start the cleanup process
    case EblParserStateFinalize:
      // Get data
      // Don't hash, don't decrypt
      retval = ebl_getData(context,
			   &input,
			   tagBuffer,
			   4UL,
			   false,
			   false);
      if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	return retval;
      }

      // Check CRC
      if (parserContext->fileCrc != BTL_CRC32_END) {
	parserContext->internalState = EblParserStateError;
	return BOOTLOADER_ERROR_PARSER_CRC;
      }

      if (!parser_requireAuthenticity()) {
	// Set image as verified if verification is not required
	imageProperties->imageVerified = true;
      }

      // Flash withheld information now if authenticity was not required
      // or we have verified the signature. CRC is OK, otherwise we'd have
      // errored.
      if (imageProperties->imageVerified) {
	// We have a bootloader PC/SE length to write
	if ((parserContext->receivedFlags
	     & (BTL_PARSER_RECEIVED_BOOTLOADER | BTL_PARSER_RECEIVED_SE))
	    && (callbacks->bootloaderCallback != NULL)) {
	  callbacks->bootloaderCallback(4UL,
					parserContext->withheldBootloaderVectors,
					4U,
					callbacks->context);
	}
	// If programmingAddress != 0, we have an application PC to write
	if ((parserContext->programmingAddress != 0UL)
	    && (callbacks->applicationCallback != NULL)) {
	  temporaryWord = 0xFFFFFFFFUL;
	  if (memcmp(&temporaryWord, parserContext->withheldUpgradeVectors, 4U) != 0) {
	    // Data has been withheld from the bootloader upgrade area
	    uint32_t btlUpgradeAddress = parser_getBootloaderUpgradeAddress();
	    if (btlUpgradeAddress > 0UL) {
	      // Bootloader upgrade address is valid
	      callbacks->applicationCallback(btlUpgradeAddress + 4UL,
					     parserContext->withheldUpgradeVectors,
					     4U,
					     callbacks->context);
	    }
	  }

	  if (memcmp(&temporaryWord, parserContext->withheldApplicationVectors, 4U) != 0) {
	    // Data has been withheld from the application vector table
	    // Return everything but the program counter
	    callbacks->applicationCallback(parser_getApplicationAddress() + 8UL,
					   &parserContext->withheldApplicationVectors[4],
					   20U,
					   callbacks->context);
	    // To ensure safe operation if a power loss occurs, return the
	    // program counter last. If secure boot is not enabled, the
	    // presence of a valid PC signals that the application is valid.
	    callbacks->applicationCallback(parser_getApplicationAddress() + 4UL,
					   parserContext->withheldApplicationVectors,
					   4U,
					   callbacks->context);
	  }
	}
      }

      // Report done to bootloader
      imageProperties->imageCompleted = true;
      parserContext->internalState = EblParserStateDone;
      return BOOTLOADER_OK;
      break;

      // Completely done with the file, in this state we'll stop processing.
    case EblParserStateDone:
      return BOOTLOADER_ERROR_PARSER_EOF;
      break;

      // Received an encryption initialization header,
      // so initialize the encryption state
    case EblParserStateEncryptionInit:
#ifndef BTL_PARSER_NO_SUPPORT_ENCRYPTION
      // This is a fixed size header, so let's get it all at once.
      while (parserContext->offsetInTag < 16UL) {
	// Get data
	// Hash, but don't decrypt, since ENC_INIT is always in the clear
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     16UL,
			     true,
			     false);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	// Initialize AES-CCM
	btl_initAesCcm(parserContext->aesContext,
		       0x02U,
		       &(tagBuffer[4]),
		       1UL, // Ember starts counter at 1?
		       btl_getImageFileEncryptionKeyPtr(),
		       128UL);
      }

      parserContext->internalState = EblParserStateIdle;
#else
      return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
#endif
      break;

      // This tag contains encrypted tags, so set up decryption
      // and go one level down in the state machine
    case EblParserStateEncryptionContainer:
#ifndef BTL_PARSER_NO_SUPPORT_ENCRYPTION
      parserContext->inEncryptedContainer = true;
      parserContext->internalState = EblParserStateIdle;
#else
      return BOOTLOADER_ERROR_PARSER_UNEXPECTED;
#endif
      break;
#if defined(BTL_SUPPORT_CERTIFICATES)
    case EblParserStateCertificate:
      if (!parserContext->gotCertificate) {
	if (parserContext->offsetInTag < 4UL) {
	  // Get version of the certificate struct
	  retval = ebl_getData(context,
			       &input,
			       tagBuffer,
			       4UL,
			       true,
			       false);
	  if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	    return retval;
	  }
	  memcpy(&(parserContext->certificate.structVersion), tagBuffer, 4U);
	} else if (parserContext->offsetInTag < 68UL) {
	  // Get ECDSA public key.
	  retval = ebl_getData(context,
			       &input,
			       tagBuffer,
			       64UL,
			       true,
			       false);
	  if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	    return retval;
	  }
	  // Save ECDSA public key in the context
	  // for verification of the GBL.
	  memcpy(parserContext->certificate.key, tagBuffer, 64U);
	} else if (parserContext->offsetInTag < 72UL) {
	  // Get version of this certificate.
	  retval = ebl_getData(context,
			       &input,
			       tagBuffer,
			       4UL,
			       true,
			       false);
	  if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	    return retval;
	  }
	  memcpy(&(parserContext->certificate.version), tagBuffer, 4U);

	  // Access word 13 to read sl_app_properties of the bootloader.
	  ApplicationProperties_t *blProperties = (ApplicationProperties_t *)(*(uint32_t *)(BTL_MAIN_STAGE_BASE + 52UL));
	  if ((blProperties->cert == NULL) || (blProperties->cert->version > parserContext->certificate.version)) {
	    BTL_DEBUG_PRINTLN("Certificate does not exist or the version of the cert is too low");
	    parserContext->internalState = EblParserStateError;
	    return BOOTLOADER_ERROR_PARSER_REJECTED;
	  }
	} else {
	  // Get signature of the certificate.
	  retval = ebl_getData(context,
			       &input,
			       tagBuffer,
			       64UL,
			       true,
			       false);
	  if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	    return retval;
	  }
	  memcpy(parserContext->certificate.signature, tagBuffer, 64U);
	  // SHA-256 of the certificate.
	  Sha256Context_t shaState;
	  btl_initSha256(&shaState);
	  btl_updateSha256(&shaState,
			   (const uint8_t*)&(parserContext->certificate),
			   72U);
	  btl_finalizeSha256(&shaState);

	  // Use the public key stored in SE to verify the certificate.
	  retval = btl_verifyEcdsaP256r1(shaState.sha,
					 &(parserContext->certificate.signature[0]),
					 &(parserContext->certificate.signature[32]),
					 NULL,
					 NULL);

	  if (retval != BOOTLOADER_OK) {
	    BTL_DEBUG_PRINTLN("Certificate verify fail");
	    parserContext->internalState = EblParserStateError;
	    return BOOTLOADER_ERROR_PARSER_SIGNATURE;
	  }
	  parserContext->gotCertificate = true;
	  parserContext->internalState = EblParserStateIdle;
	}
      }
      break;
#endif
      // This tag contains the signature over the entire EBL,
      // accept no more data hereafter.
    case EblParserStateSignature:
      // Make sure we have the necessary data
      if (!(parserContext->gotSignature)) {
	// Get data
	// No hashing (tag is unhashed), obviously no decryption
	retval = ebl_getData(context,
			     &input,
			     tagBuffer,
			     64UL,
			     false,
			     false);
	if (retval != BOOTLOADER_ERROR_PARSER_PARSED) {
	  return retval;
	}

	btl_finalizeSha256(parserContext->shaContext);
	  

#if defined(BTL_SUPPORT_CERTIFICATES)
	if (parserContext->gotCertificate) {
	  retval = btl_verifyEcdsaP256r1(parserContext->shaContext,
					 &tagBuffer[0],
					 &tagBuffer[32],
					 &(parserContext->certificate.key[0]),
					 &(parserContext->certificate.key[32]));
	} else {
	  // Received direct signed GBL
	  retval = btl_verifyEcdsaP256r1(parserContext->shaContext,
					 &tagBuffer[0],
					 &tagBuffer[32],
					 btl_getSignedBootloaderKeyXPtr(),
					 btl_getSignedBootloaderKeyYPtr());
	}
#else
	retval = btl_verifyEcdsaP256r1(parserContext->shaContext,
				       &tagBuffer[0],
				       &tagBuffer[32],
				       btl_getSignedBootloaderKeyXPtr(),
				       btl_getSignedBootloaderKeyYPtr());
#endif
	if (retval != BOOTLOADER_OK) {
	  BTL_DEBUG_PRINTLN("EBL verify fail");
	  imageProperties->imageVerified = false;
	  parserContext->internalState = EblParserStateError;
	  return BOOTLOADER_ERROR_PARSER_SIGNATURE;
	} else {
	  imageProperties->imageVerified = true;
	}

	parserContext->gotSignature = true;
      }

      parserContext->internalState = EblParserStateIdle;
      break;
    case EblParserStateError:
      return BOOTLOADER_ERROR_PARSER_EOF;
      break;
      // No default statement here guarantees a compile-time check
      // that we caught all states
    }
  }

  // If we get here, we landed right on a tag boundary...
  return BOOTLOADER_OK;
}
