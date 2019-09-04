//
//  RangeReplaceableCollection_Extensions.swift
//  BitcoinKit
//
//  Created by Alexander Cyon on 2019-09-04.
//  Copyright © 2019 BitcoinKit developers. All rights reserved.
//

import Foundation

extension RangeReplaceableCollection {

    mutating func prepend(element: Element, toLength expectedLength: Int?) {
        self = prepending(element: element, toLength: expectedLength)
    }

    func prepending(element: Element, toLength expectedLength: Int?) -> Self {
        guard let expectedLength = expectedLength else {
            return self
        }
        var modified = self
        while modified.count < expectedLength {
            modified = [element] + modified
        }
        return modified
    }

    mutating func append(element: Element, toLength expectedLength: Int?) {
          self = appending(element: element, toLength: expectedLength)
      }

      func appending(element: Element, toLength expectedLength: Int?) -> Self {
          guard let expectedLength = expectedLength else {
              return self
          }
          var modified = self
          while modified.count < expectedLength {
            modified.append(element)
          }
          return modified
      }
}
