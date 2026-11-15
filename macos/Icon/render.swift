// Renders the icon drawing to one PNG of the given pixel size, with the OS's own SVG support:
//   swift macos/Icon/render.swift <in.svg> <out.png> <pixels>
import AppKit

let args = CommandLine.arguments
guard args.count == 4, let px = Int(args[3]), px > 0,
      let data = FileManager.default.contents(atPath: args[1]),
      let image = NSImage(data: data),
      let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px,
                                 bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                 colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
else {
    FileHandle.standardError.write(Data("usage: render.swift <in.svg> <out.png> <pixels>\n".utf8))
    exit(2)
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
image.draw(in: NSRect(x: 0, y: 0, width: px, height: px))
NSGraphicsContext.restoreGraphicsState()
guard let png = rep.representation(using: .png, properties: [:]),
      FileManager.default.createFile(atPath: args[2], contents: png)
else {
    exit(1)
}
